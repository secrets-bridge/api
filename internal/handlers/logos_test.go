package handlers_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/objectstore"
	"github.com/secrets-bridge/api/pkg/objectstore/objectstoretest"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Project and team logos: upload checks, re-encoding, the read scope of
// the image, logo_version on bodies and value-free audit metadata.
//
// The route-level team.edit gate on PUT/DELETE is registered in main
// like the other project writes and covered by
// TestTenancyWrites_RequireTeamEdit in cmd/api; these tests exercise
// the handlers.

type logoFixture struct {
	app          *fiber.App
	pool         *storage.Pool
	admin        uuid.UUID // global secret.list + secret.request + team.edit
	outsider     uuid.UUID // secret.list on otherProject only
	project      uuid.UUID
	otherProject uuid.UUID
	team         uuid.UUID
	svc          *services.LogoService
	store        objectstore.Store // nil: object storage not configured
}

// testLogoStore is the object store the logo handler tests run on: the
// live S3-compatible server when TEST_OBJECTSTORE_ENDPOINT is set (CI
// sets it, with MinIO), the in-memory store otherwise.
func testLogoStore(t *testing.T) (objectstore.Store, objectstore.Config) {
	t.Helper()
	if os.Getenv(objectstoretest.EnvTestEndpoint) != "" {
		return objectstoretest.Live(t)
	}
	return objectstoretest.NewMemory(), objectstore.Config{Bucket: "example-bucket", Prefix: "test"}
}

func bootstrapLogos(t *testing.T) *logoFixture {
	t.Helper()
	store, keys := testLogoStore(t)
	return bootstrapLogosWith(t, store, keys)
}

// bootstrapLogosWith wires the fixture on the given store; nil means no
// object storage configured.
func bootstrapLogosWith(t *testing.T, store objectstore.Store, keys objectstore.Config) *logoFixture {
	t.Helper()
	enableHeaderIdentityForTest(t)
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 4, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	const wipe = `
		DELETE FROM project_logos;
		DELETE FROM team_logos;
		DELETE FROM reveal_sessions;
		DELETE FROM secret_wraps;
		DELETE FROM approvals;
		DELETE FROM sync_jobs;
		DELETE FROM access_requests;
		DELETE FROM project_secrets;
		DELETE FROM secrets;
		DELETE FROM team_members;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM environments;
		DELETE FROM projects;
		DELETE FROM teams;
		DELETE FROM local_users;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}

	fx := &logoFixture{pool: pool, project: uuid.New(), otherProject: uuid.New()}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1,'billing'),($2,'ledger')`,
		fx.project, fx.otherProject); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	teamsRepo := storage.NewTeams(pool)
	team := &storage.Team{Name: "payments"}
	if err := teamsRepo.Create(ctx, team); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	fx.team = team.ID

	fx.admin = seedUserWithGrant(t, pool, "logo-admin", `["secret.list","secret.request","team.edit"]`, "{}")
	fx.outsider = seedUserWithGrant(t, pool, "logo-outsider", `["secret.list"]`,
		`{"project_id":"`+fx.otherProject.String()+`"}`)
	if _, err := pool.Exec(ctx,
		`INSERT INTO local_users (id, email, password_hash, display_name) VALUES ($1,'admin@example.com','\x00','Admin')`,
		fx.admin); err != nil {
		t.Fatalf("seed local user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO team_members (team_id, user_id) VALUES ($1,$2)`, fx.team, fx.admin); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	projectRepo := storage.NewProjects(pool)
	resolver := auth.NewRepoResolver(storage.NewUserRoles(pool), storage.NewRoles(pool))
	tsr := auth.NewRepoTeamScopeResolver(teamsRepo, projectRepo)
	logoSvc := services.NewLogoService(storage.NewLogos(pool), projectRepo, teamsRepo, storage.NewAuditEvents(pool))
	if store != nil {
		logoSvc = logoSvc.WithStore(store, keys)
	}
	fx.svc, fx.store = logoSvc, store

	tenancyH := handlers.NewTenancy(projectRepo, storage.NewEnvironments(pool)).WithScope(resolver, tsr).WithLogos(logoSvc)
	teamsH := handlers.NewTeams(teamsRepo).WithLogos(logoSvc)
	meH := handlers.NewMe(projectRepo, resolver).WithTeamScope(tsr).
		WithIdentity(storage.NewLocalUsers(pool), teamsRepo).WithLogos(logoSvc)

	app := fiber.New()
	app.Use(middleware.Auth())
	app.Get("/api/v1/projects", tenancyH.ListProjects)
	app.Get("/api/v1/projects/:id", tenancyH.GetProject)
	app.Get("/api/v1/projects/:id/logo", tenancyH.GetProjectLogo)
	app.Put("/api/v1/projects/:id/logo", tenancyH.PutProjectLogo)
	app.Delete("/api/v1/projects/:id/logo", tenancyH.DeleteProjectLogo)
	app.Get("/api/v1/teams", teamsH.List)
	app.Get("/api/v1/teams/:id", teamsH.Get)
	app.Get("/api/v1/teams/:id/logo", teamsH.GetTeamLogo)
	app.Put("/api/v1/teams/:id/logo", teamsH.PutTeamLogo)
	app.Delete("/api/v1/teams/:id/logo", teamsH.DeleteTeamLogo)
	app.Get("/api/v1/users/me", meH.GetMe)
	fx.app = app
	return fx
}

type logoResp struct {
	status int
	header http.Header
	body   []byte
}

func (fx *logoFixture) do(t *testing.T, method, path string, user uuid.UUID, contentType string, body []byte, hdr map[string]string) logoResp {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("X-User-Id", user.String())
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return logoResp{status: resp.StatusCode, header: resp.Header, body: b}
}

// testImage is a w×h image with a simple gradient, so the encoders have
// real pixels to work with.
func testImage(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 255 / w), G: uint8(y * 255 / h), B: 120, A: 255})
		}
	}
	return img
}

func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, testImage(w, h)); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func jpegBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, testImage(w, h), &jpeg.Options{Quality: 80}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return buf.Bytes()
}

// photoJPEG is a w×h JPEG of a noisy gradient, like a photo: small as a
// JPEG, much larger as a PNG of the same size.
func photoJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	rng := rand.New(rand.NewPCG(1, 2))
	noisy := func(v int) uint8 { return uint8(max(0, min(255, v+rng.IntN(17)-8))) }
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: noisy(x * 255 / w), G: noisy(y * 255 / h), B: noisy(120 + (x+y)%40), A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 75}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return buf.Bytes()
}

// withTextChunk inserts a tEXt chunk after IHDR, the way image tools
// store comments and other metadata.
func withTextChunk(t *testing.T, p []byte, text string) []byte {
	t.Helper()
	const sig = 8
	ihdrLen := int(binary.BigEndian.Uint32(p[sig : sig+4]))
	end := sig + 12 + ihdrLen // length + type + data + crc
	data := []byte(text)
	chunk := make([]byte, 0, 12+len(data))
	chunk = binary.BigEndian.AppendUint32(chunk, uint32(len(data)))
	chunk = append(chunk, "tEXt"...)
	chunk = append(chunk, data...)
	chunk = binary.BigEndian.AppendUint32(chunk, crc32.ChecksumIEEE(append([]byte("tEXt"), data...)))
	out := append([]byte{}, p[:end]...)
	out = append(out, chunk...)
	return append(out, p[end:]...)
}

func decodeVersion(t *testing.T, r logoResp) string {
	t.Helper()
	var v struct {
		LogoVersion string `json:"logo_version"`
	}
	if err := json.Unmarshal(r.body, &v); err != nil || v.LogoVersion == "" {
		t.Fatalf("logo_version missing: %d %s", r.status, r.body)
	}
	return v.LogoVersion
}

func TestLogo_RoundTripReencodesAndServesAsImage(t *testing.T) {
	fx := bootstrapLogos(t)
	path := "/api/v1/projects/" + fx.project.String() + "/logo"

	upload := withTextChunk(t, pngBytes(t, 64, 64), "Comment\x00drop-me-please")
	put := fx.do(t, http.MethodPut, path, fx.admin, "image/png", upload, nil)
	if put.status != http.StatusOK {
		t.Fatalf("PUT: %d %s", put.status, put.body)
	}
	version := decodeVersion(t, put)
	if len(version) != 12 {
		t.Fatalf("logo_version %q: want 12 hex characters", version)
	}

	get := fx.do(t, http.MethodGet, path, fx.admin, "", nil, nil)
	if get.status != http.StatusOK {
		t.Fatalf("GET: %d %s", get.status, get.body)
	}
	sum := sha256.Sum256(get.body)
	digest := hex.EncodeToString(sum[:])
	if digest[:12] != version {
		t.Fatalf("served image digest %s does not match logo_version %s", digest[:12], version)
	}
	want := map[string]string{
		"Content-Type":            "image/png",
		"Cache-Control":           "private, max-age=31536000, immutable",
		"Etag":                    `"` + digest + `"`,
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"Content-Disposition":     `inline; filename="logo.png"`,
	}
	for k, v := range want {
		if got := get.header.Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(get.body))
	if err != nil || cfg.Width != 64 || cfg.Height != 64 {
		t.Fatalf("served image is not a 64x64 PNG: %v %+v", err, cfg)
	}
	if bytes.Contains(get.body, []byte("drop-me-please")) {
		t.Fatal("metadata chunk survived re-encoding")
	}

	notModified := fx.do(t, http.MethodGet, path, fx.admin, "", nil, map[string]string{"If-None-Match": `"` + digest + `"`})
	if notModified.status != http.StatusNotModified || len(notModified.body) != 0 {
		t.Fatalf("If-None-Match: %d (%d bytes), want 304 with no body", notModified.status, len(notModified.body))
	}
}

func TestLogo_JPEGIsStoredAsPNG(t *testing.T) {
	fx := bootstrapLogos(t)
	path := "/api/v1/teams/" + fx.team.String() + "/logo"
	put := fx.do(t, http.MethodPut, path, fx.admin, "image/jpeg", jpegBytes(t, 96, 80), nil)
	if put.status != http.StatusOK {
		t.Fatalf("PUT jpeg: %d %s", put.status, put.body)
	}
	get := fx.do(t, http.MethodGet, path, fx.outsider, "", nil, nil)
	if get.status != http.StatusOK || !bytes.HasPrefix(get.body, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("team logo: %d, PNG signature %v", get.status, bytes.HasPrefix(get.body, []byte("\x89PNG")))
	}
}

// A photo-like JPEG used to be refused as over 64 KiB: re-encoded as a
// 16-bit PNG at full size it was hundreds of KiB. It is now stored as an
// 8-bit PNG at most 128 px on the longer side.
func TestLogo_PhotoJPEGIsScaledToFit(t *testing.T) {
	fx := bootstrapLogos(t)
	path := "/api/v1/projects/" + fx.project.String() + "/logo"
	upload := photoJPEG(t, 512, 384)
	if len(upload) > services.LogoMaxBytes {
		t.Fatalf("fixture is %d bytes, over the upload cap", len(upload))
	}
	if put := fx.do(t, http.MethodPut, path, fx.admin, "image/jpeg", upload, nil); put.status != http.StatusOK {
		t.Fatalf("PUT: %d %s", put.status, put.body)
	}
	get := fx.do(t, http.MethodGet, path, fx.admin, "", nil, nil)
	if get.status != http.StatusOK {
		t.Fatalf("GET: %d %s", get.status, get.body)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(get.body))
	if err != nil {
		t.Fatalf("stored logo is not a PNG: %v", err)
	}
	if cfg.Width != 128 || cfg.Height != 96 {
		t.Errorf("stored %dx%d, want 128x96 (longer side 128, aspect kept)", cfg.Width, cfg.Height)
	}
	if cfg.ColorModel != color.RGBAModel {
		t.Errorf("stored color model %T, want 8-bit RGB", cfg.ColorModel)
	}
	if len(get.body) > services.LogoMaxBytes {
		t.Errorf("stored %d bytes, over the cap", len(get.body))
	}
}

func TestLogo_RefusesWhatItCannotStore(t *testing.T) {
	fx := bootstrapLogos(t)
	path := "/api/v1/projects/" + fx.project.String() + "/logo"
	big := make([]byte, 70*1024)
	copy(big, pngBytes(t, 32, 32))

	cases := []struct {
		name        string
		contentType string
		body        []byte
		want        int
	}{
		{"svg", "image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), http.StatusUnsupportedMediaType},
		{"gif", "image/gif", []byte("GIF89a"), http.StatusUnsupportedMediaType},
		{"no content type", "", pngBytes(t, 32, 32), http.StatusUnsupportedMediaType},
		{"over 64 KiB", "image/png", big, http.StatusRequestEntityTooLarge},
		{"too small", "image/png", pngBytes(t, 8, 8), http.StatusUnprocessableEntity},
		{"too large", "image/png", pngBytes(t, 600, 40), http.StatusUnprocessableEntity},
		{"not an image", "image/png", []byte("this is not a png"), http.StatusUnprocessableEntity},
		{"declared png, sent jpeg", "image/png", jpegBytes(t, 32, 32), http.StatusUnprocessableEntity},
		{"empty", "image/png", []byte{}, http.StatusUnprocessableEntity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fx.do(t, http.MethodPut, path, fx.admin, tc.contentType, tc.body, nil)
			if r.status != tc.want {
				t.Fatalf("status %d, want %d: %s", r.status, tc.want, r.body)
			}
		})
	}
	if r := fx.do(t, http.MethodGet, path, fx.admin, "", nil, nil); r.status != http.StatusNotFound {
		t.Fatalf("a refused upload left a logo: %d", r.status)
	}
	missing := fx.do(t, http.MethodPut, "/api/v1/projects/"+uuid.New().String()+"/logo", fx.admin, "image/png", pngBytes(t, 32, 32), nil)
	if missing.status != http.StatusNotFound || !strings.Contains(string(missing.body), "project not found") {
		t.Fatalf("PUT for a missing project: %d %s", missing.status, missing.body)
	}
	// The owner is checked before the body is decoded: bytes that are not
	// an image still get 404 for a project that doesn't exist.
	unread := fx.do(t, http.MethodPut, "/api/v1/projects/"+uuid.New().String()+"/logo", fx.admin, "image/png", []byte("not a png"), nil)
	if unread.status != http.StatusNotFound {
		t.Fatalf("PUT garbage for a missing project: %d %s, want 404", unread.status, unread.body)
	}
}

func TestLogo_DeleteThenGone(t *testing.T) {
	fx := bootstrapLogos(t)
	path := "/api/v1/projects/" + fx.project.String() + "/logo"
	if r := fx.do(t, http.MethodPut, path, fx.admin, "image/png", pngBytes(t, 32, 32), nil); r.status != http.StatusOK {
		t.Fatalf("PUT: %d %s", r.status, r.body)
	}
	if r := fx.do(t, http.MethodDelete, path, fx.admin, "", nil, nil); r.status != http.StatusNoContent {
		t.Fatalf("DELETE: %d %s", r.status, r.body)
	}
	if r := fx.do(t, http.MethodGet, path, fx.admin, "", nil, nil); r.status != http.StatusNotFound {
		t.Fatalf("GET after delete: %d", r.status)
	}
	if r := fx.do(t, http.MethodDelete, path, fx.admin, "", nil, nil); r.status != http.StatusNotFound {
		t.Fatalf("second DELETE: %d", r.status)
	}
}

func TestLogo_ProjectLogoFollowsProjectReadScope(t *testing.T) {
	fx := bootstrapLogos(t)
	for _, id := range []uuid.UUID{fx.project, fx.otherProject} {
		if r := fx.do(t, http.MethodPut, "/api/v1/projects/"+id.String()+"/logo", fx.admin, "image/png", pngBytes(t, 32, 32), nil); r.status != http.StatusOK {
			t.Fatalf("PUT %s: %d %s", id, r.status, r.body)
		}
	}
	hidden := fx.do(t, http.MethodGet, "/api/v1/projects/"+fx.project.String()+"/logo", fx.outsider, "", nil, nil)
	if hidden.status != http.StatusNotFound || bytes.HasPrefix(hidden.body, []byte("\x89PNG")) {
		t.Fatalf("out-of-scope logo: %d, want 404 without the image", hidden.status)
	}
	visible := fx.do(t, http.MethodGet, "/api/v1/projects/"+fx.otherProject.String()+"/logo", fx.outsider, "", nil, nil)
	if visible.status != http.StatusOK {
		t.Fatalf("in-scope logo: %d %s", visible.status, visible.body)
	}
}

func TestLogo_VersionOnBodies(t *testing.T) {
	fx := bootstrapLogos(t)
	projectPath := "/api/v1/projects/" + fx.project.String()
	teamPath := "/api/v1/teams/" + fx.team.String()

	var before struct {
		LogoVersion *string `json:"logo_version"`
	}
	r := fx.do(t, http.MethodGet, projectPath, fx.admin, "", nil, nil)
	if err := json.Unmarshal(r.body, &before); err != nil || before.LogoVersion != nil || !strings.Contains(string(r.body), `"logo_version":null`) {
		t.Fatalf("project without logo: want logo_version null, got %s", r.body)
	}

	pv := decodeVersion(t, fx.do(t, http.MethodPut, projectPath+"/logo", fx.admin, "image/png", pngBytes(t, 32, 32), nil))
	tv := decodeVersion(t, fx.do(t, http.MethodPut, teamPath+"/logo", fx.admin, "image/png", pngBytes(t, 48, 48), nil))

	check := func(name, body, id, want string) {
		t.Helper()
		if !strings.Contains(body, id) || !strings.Contains(body, `"logo_version":"`+want+`"`) {
			t.Errorf("%s: logo_version %s for %s missing in %s", name, want, id, body)
		}
	}
	check("GET /projects/:id", string(fx.do(t, http.MethodGet, projectPath, fx.admin, "", nil, nil).body), fx.project.String(), pv)
	list := string(fx.do(t, http.MethodGet, "/api/v1/projects", fx.admin, "", nil, nil).body)
	check("GET /projects", list, fx.project.String(), pv)
	if !strings.Contains(list, `"logo_version":null`) {
		t.Errorf("GET /projects: the project without a logo should report null: %s", list)
	}
	check("GET /teams/:id", string(fx.do(t, http.MethodGet, teamPath, fx.admin, "", nil, nil).body), fx.team.String(), tv)
	check("GET /teams", string(fx.do(t, http.MethodGet, "/api/v1/teams", fx.admin, "", nil, nil).body), fx.team.String(), tv)

	me := fx.do(t, http.MethodGet, "/api/v1/users/me", fx.admin, "", nil, nil)
	if me.status != http.StatusOK {
		t.Fatalf("GET /users/me: %d %s", me.status, me.body)
	}
	var body struct {
		Projects []struct {
			ID          string  `json:"id"`
			LogoVersion *string `json:"logo_version"`
		} `json:"projects"`
		Teams []struct {
			ID          string  `json:"id"`
			LogoVersion *string `json:"logo_version"`
		} `json:"teams"`
	}
	if err := json.Unmarshal(me.body, &body); err != nil {
		t.Fatalf("decode /users/me: %v", err)
	}
	found := 0
	for _, p := range body.Projects {
		switch p.ID {
		case fx.project.String():
			found++
			if p.LogoVersion == nil || *p.LogoVersion != pv {
				t.Errorf("/users/me project logo_version = %v, want %s", p.LogoVersion, pv)
			}
		case fx.otherProject.String():
			found++
			if p.LogoVersion != nil {
				t.Errorf("/users/me project without a logo reports %s", *p.LogoVersion)
			}
		}
	}
	if found != 2 {
		t.Errorf("/users/me listed %d of the 2 projects: %s", found, me.body)
	}
	if len(body.Teams) != 1 || body.Teams[0].LogoVersion == nil || *body.Teams[0].LogoVersion != tv {
		t.Errorf("/users/me team logo_version: %s", me.body)
	}
}

func TestLogo_AuditCarriesNoImageBytes(t *testing.T) {
	fx := bootstrapLogos(t)
	upload := pngBytes(t, 40, 40)
	projectPath := "/api/v1/projects/" + fx.project.String() + "/logo"
	if r := fx.do(t, http.MethodPut, projectPath, fx.admin, "image/png", upload, nil); r.status != http.StatusOK {
		t.Fatalf("PUT: %d %s", r.status, r.body)
	}
	stored := fx.do(t, http.MethodGet, projectPath, fx.admin, "", nil, nil).body
	if r := fx.do(t, http.MethodDelete, projectPath, fx.admin, "", nil, nil); r.status != http.StatusNoContent {
		t.Fatalf("DELETE: %d", r.status)
	}
	if r := fx.do(t, http.MethodPut, "/api/v1/teams/"+fx.team.String()+"/logo", fx.admin, "image/png", upload, nil); r.status != http.StatusOK {
		t.Fatalf("PUT team: %d", r.status)
	}

	rows, err := fx.pool.Query(t.Context(),
		`SELECT action, resource, actor, correlation_id, metadata::text FROM audit_events WHERE action LIKE '%.logo.%' ORDER BY occurred_at`)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action, resource, actor, meta string
		var corr uuid.UUID
		if err := rows.Scan(&action, &resource, &actor, &corr, &meta); err != nil {
			t.Fatalf("scan: %v", err)
		}
		actions = append(actions, action)
		if corr == uuid.Nil {
			t.Errorf("%s: no correlation id", action)
		}
		if actor != "user:"+fx.admin.String() {
			t.Errorf("%s: actor %q", action, actor)
		}
		if !strings.HasPrefix(resource, "project:") && !strings.HasPrefix(resource, "team:") {
			t.Errorf("%s: resource %q", action, resource)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(meta), &m); err != nil {
			t.Fatalf("%s: metadata: %v", action, err)
		}
		if len(m) != 4 || m["byte_length"] == nil || m["sha256"] == nil || m["width"] == nil || m["height"] == nil {
			t.Errorf("%s: metadata keys %v, want byte_length, sha256, width, height", action, m)
		}
		for _, b := range [][]byte{upload, stored} {
			if strings.Contains(meta, hex.EncodeToString(b[:16])) || strings.Contains(meta, "PNG") {
				t.Errorf("%s: metadata carries image bytes: %s", action, meta)
			}
		}
	}
	want := []string{"project.logo.updated", "project.logo.removed", "team.logo.updated"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("audit actions %v, want %v", actions, want)
	}
}
