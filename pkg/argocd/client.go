package argocd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config carries the per-endpoint runtime configuration.
type Config struct {
	BaseURL       string
	Token         string // plaintext; the service layer unwraps from KMS before passing
	TLSCAPEM      string // optional; replaces system roots when set
	TLSServerName string // optional; SNI override
	Timeout       time.Duration
}

// Client is the read-only ArgoCD HTTP client. Constructed via New.
//
// SAFETY: the embedded http.Client uses readOnlyTransport which
// rejects every method other than GET. There is no path through this
// type that can issue a write to ArgoCD.
type Client struct {
	base    string
	token   string
	hc      *http.Client
	tlsCfg  *tls.Config
}

// ErrWriteRefused is returned by the read-only transport if a caller
// attempts a non-GET request. Useful as a sanity check in tests.
var ErrWriteRefused = errors.New("argocd: read-only transport refused non-GET request")

// ErrUnauthorized maps ArgoCD 401.
var ErrUnauthorized = errors.New("argocd: unauthorized")

// ErrForbidden maps ArgoCD 403. Usually means the token's RBAC denies
// the requested verb — a signal the self-check should have caught at
// boot.
var ErrForbidden = errors.New("argocd: forbidden")

// ErrNotFound maps ArgoCD 404.
var ErrNotFound = errors.New("argocd: not found")

// New builds a Client. Returns an error only for malformed BaseURL or
// invalid TLS material.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("argocd: BaseURL is required")
	}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("argocd: BaseURL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("argocd: BaseURL scheme must be https (or http for dev)")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.TLSCAPEM)) {
			return nil, errors.New("argocd: TLSCAPEM contains no usable certificates")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.TLSServerName != "" {
		tlsCfg.ServerName = cfg.TLSServerName
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	hc := &http.Client{
		Timeout: timeout,
		Transport: &readOnlyTransport{
			next: &http.Transport{
				TLSClientConfig: tlsCfg,
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}
	return &Client{
		base:   strings.TrimRight(cfg.BaseURL, "/"),
		token:  cfg.Token,
		hc:     hc,
		tlsCfg: tlsCfg,
	}, nil
}

// readOnlyTransport is the load-bearing guard: it refuses any method
// other than GET before the request leaves the process. Even if a
// future bug builds a POST elsewhere in the code, it never hits the
// network.
type readOnlyTransport struct {
	next http.RoundTripper
}

func (r *readOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, ErrWriteRefused
	}
	return r.next.RoundTrip(req)
}

// Application is the trimmed status shape we surface to operators.
// Manifests are NEVER carried; only filtered status fields per
// BRD §26.4.
//
// `Namespace` is the namespace of the ArgoCD Application CR itself
// (usually "argocd"). `DestinationNamespace` is the namespace where
// the application's resources actually land — this is the field the
// gitops mapping creator's "namespace" column should mirror.
type Application struct {
	Name                 string                `json:"name"`
	Namespace            string                `json:"namespace,omitempty"`
	Project              string                `json:"project,omitempty"`
	DestinationServer    string                `json:"destination_server,omitempty"`
	DestinationCluster   string                `json:"destination_cluster,omitempty"`
	DestinationNamespace string                `json:"destination_namespace,omitempty"`
	HealthStatus         string                `json:"health_status,omitempty"`   // Healthy / Progressing / Degraded / Missing / Unknown
	HealthMessage        string                `json:"health_message,omitempty"`
	SyncStatus           string                `json:"sync_status,omitempty"`     // Synced / OutOfSync / Unknown
	SyncRevision         string                `json:"sync_revision,omitempty"`
	OperationPhase       string                `json:"operation_phase,omitempty"` // Running / Succeeded / Failed / Error
	Resources            []ApplicationResource `json:"resources,omitempty"`
}

// ApplicationResource is one child resource (Deployment, StatefulSet,
// Pod, etc.) of an ArgoCD application. Health is the only status
// field we surface; spec / manifest is NEVER returned.
type ApplicationResource struct {
	Group     string `json:"group,omitempty"`
	Version   string `json:"version,omitempty"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Status    string `json:"status,omitempty"`   // ArgoCD sync status for the resource
	Health    string `json:"health,omitempty"`   // Healthy / Progressing / ...
	Message   string `json:"message,omitempty"`
}

// rawApplication mirrors enough of ArgoCD's /api/v1/applications/{name}
// response to populate Application without dragging the full schema.
type rawApplication struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Project     string `json:"project"`
		Destination struct {
			Server    string `json:"server"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"destination"`
	} `json:"spec"`
	Status struct {
		Health struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"health"`
		Sync struct {
			Status   string `json:"status"`
			Revision string `json:"revision"`
		} `json:"sync"`
		OperationState *struct {
			Phase   string `json:"phase"`
			Message string `json:"message"`
		} `json:"operationState"`
	} `json:"status"`
}

// rawResourceTree mirrors enough of /resource-tree.
type rawResourceTree struct {
	Nodes []struct {
		Group     string `json:"group"`
		Version   string `json:"version"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Health    *struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"health"`
	} `json:"nodes"`
}

// GetApplication fetches the application summary.
func (c *Client) GetApplication(ctx context.Context, name string) (*Application, error) {
	var raw rawApplication
	if err := c.do(ctx, "/api/v1/applications/"+url.PathEscape(name), &raw); err != nil {
		return nil, err
	}
	return appFromRaw(raw), nil
}

// ListApplications returns every application visible to the
// configured token. Use `project` to filter by ArgoCD project name
// (matches ArgoCD's own ?projects= query param); pass "" for no
// filter.
//
// Manifests are NEVER carried in the response — only the trimmed
// `Application` status fields.
func (c *Client) ListApplications(ctx context.Context, project string) ([]Application, error) {
	path := "/api/v1/applications"
	if project != "" {
		path += "?projects=" + url.QueryEscape(project)
	}
	var raw struct {
		Items []rawApplication `json:"items"`
	}
	if err := c.do(ctx, path, &raw); err != nil {
		return nil, err
	}
	out := make([]Application, 0, len(raw.Items))
	for _, item := range raw.Items {
		out = append(out, *appFromRaw(item))
	}
	return out, nil
}

// appFromRaw is the single mapping point from raw → trimmed shape so
// GetApplication and ListApplications stay consistent.
func appFromRaw(raw rawApplication) *Application {
	return &Application{
		Name:                 raw.Metadata.Name,
		Namespace:            raw.Metadata.Namespace,
		Project:              raw.Spec.Project,
		DestinationServer:    raw.Spec.Destination.Server,
		DestinationCluster:   raw.Spec.Destination.Name,
		DestinationNamespace: raw.Spec.Destination.Namespace,
		HealthStatus:         raw.Status.Health.Status,
		HealthMessage:        raw.Status.Health.Message,
		SyncStatus:           raw.Status.Sync.Status,
		SyncRevision:         raw.Status.Sync.Revision,
		OperationPhase:       phaseOrEmpty(raw),
	}
}

func phaseOrEmpty(raw rawApplication) string {
	if raw.Status.OperationState == nil {
		return ""
	}
	return raw.Status.OperationState.Phase
}

// GetApplicationResources fetches the resource list (no manifests).
func (c *Client) GetApplicationResources(ctx context.Context, name string) ([]ApplicationResource, error) {
	tree, err := c.getResourceTree(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]ApplicationResource, 0, len(tree.Nodes))
	for _, n := range tree.Nodes {
		r := ApplicationResource{
			Group:     n.Group,
			Version:   n.Version,
			Kind:      n.Kind,
			Name:      n.Name,
			Namespace: n.Namespace,
		}
		if n.Health != nil {
			r.Health = n.Health.Status
			r.Message = n.Health.Message
		}
		out = append(out, r)
	}
	return out, nil
}

// GetApplicationResourceTree returns the application + its resource tree
// in one composed call — convenient for the observation poller which
// always wants both.
func (c *Client) GetApplicationResourceTree(ctx context.Context, name string) (*Application, error) {
	app, err := c.GetApplication(ctx, name)
	if err != nil {
		return nil, err
	}
	app.Resources, err = c.GetApplicationResources(ctx, name)
	if err != nil {
		return nil, err
	}
	return app, nil
}

func (c *Client) getResourceTree(ctx context.Context, name string) (*rawResourceTree, error) {
	var tree rawResourceTree
	if err := c.do(ctx, "/api/v1/applications/"+url.PathEscape(name)+"/resource-tree", &tree); err != nil {
		return nil, err
	}
	return &tree, nil
}

// SelfCheckRBAC verifies the configured token can perform every read
// verb the integration uses — and ONLY those. The check fans through:
//
//   - GET /api/v1/applications (must succeed → confirms `applications: get` allow)
//
// The function MUST be called at boot for every configured endpoint.
// Boot fails fast if the check returns ErrUnauthorized / ErrForbidden.
//
// Note: ArgoCD does NOT expose a "what verbs do I have?" endpoint, so
// the check is positive only (confirms read works). Defense against
// over-scoped tokens is layered:
//
//	1. This function asserts read works.
//	2. The readOnlyTransport refuses to issue any non-GET request.
//	3. The integration's code path never builds a write request.
//
// Operators provide a runbook example RBAC policy (BRD §26.7) and
// hold the responsibility to scope the token to read-only verbs.
func (c *Client) SelfCheckRBAC(ctx context.Context) error {
	var ignored struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := c.do(ctx, "/api/v1/applications", &ignored); err != nil {
		return fmt.Errorf("argocd: self-check failed: %w", err)
	}
	return nil
}

// do issues a GET to path (joined with the base URL), enforces auth +
// status-code mapping, and JSON-decodes into out.
func (c *Client) do(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("argocd: build request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("argocd: %s: %w", path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
		// fall through
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	default:
		return fmt.Errorf("argocd: %s: HTTP %d", path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("argocd: decode %s: %w", path, err)
		}
	}
	return nil
}
