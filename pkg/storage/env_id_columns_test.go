package storage_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Slice L3 — verify the env_id columns round-trip on AccessRequest +
// SecretWrap + ProjectSecret, and that issued_via defaults to
// 'request' when unset.

func TestAccessRequest_EnvironmentIDRoundtrip(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()

	projectID := makeProject(t, pool, "ar-env-id")
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	if err := envRepo.Create(ctx, env); err != nil {
		t.Fatalf("env Create: %v", err)
	}

	wfRepo := storage.NewWorkflows(pool)
	wfDefault, err := wfRepo.GetDefault(ctx)
	if err != nil {
		t.Fatalf("GetDefault wf: %v", err)
	}

	repo := storage.NewAccessRequests(pool)
	req := &storage.AccessRequest{
		RequesterID:        "alice@example.com",
		Type:               storage.AccessRequestTypePatch,
		Justification:      "L3 test",
		WorkflowID:         &wfDefault.ID,
		EnvironmentID:      &env.ID,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         []string{"DB_PASSWORD"},
		TargetScope:        map[string]any{"environment": "uat", "project_id": projectID.String()},
	}
	if err := repo.Create(ctx, req); err != nil {
		t.Fatalf("Create access_request: %v", err)
	}

	got, err := repo.Get(ctx, req.ID)
	if err != nil {
		t.Fatalf("Get access_request: %v", err)
	}
	if got.EnvironmentID == nil || *got.EnvironmentID != env.ID {
		t.Errorf("EnvironmentID round-trip: got %v want %v", got.EnvironmentID, env.ID)
	}
}

func TestSecretWrap_IssuedViaDefaultsToRequest(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()

	repo := storage.NewSecretWraps(pool)
	w := &storage.SecretWrap{
		// no RequestID, no EnvironmentID, no IssuedVia — defaults exercised
		KeyName:           "DB_PASSWORD",
		EncryptedValue:    []byte("ciphertext"),
		Nonce:             []byte("aaaaaaaaaaaa"),
		DataKeyCiphertext: []byte("dek-cipher"),
		KMSKeyID:          "local:test",
		ContentHash:       []byte("hash"),
		ByteLength:        42,
		ExpiresAt:         time.Now().Add(1 * time.Hour),
	}
	if err := repo.Create(ctx, w); err != nil {
		t.Fatalf("Create wrap: %v", err)
	}
	got, err := repo.Get(ctx, w.ID)
	if err != nil {
		t.Fatalf("Get wrap: %v", err)
	}
	if got.IssuedVia != storage.WrapIssuedViaRequest {
		t.Errorf("issued_via default: got %q want %q", got.IssuedVia, storage.WrapIssuedViaRequest)
	}
	if got.EnvironmentID != nil {
		t.Errorf("EnvironmentID: got %v want nil", got.EnvironmentID)
	}
}

func TestSecretWrap_DirectRevealAndEnvIDRoundtrip(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()

	projectID := makeProject(t, pool, "wrap-env-id")
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	if err := envRepo.Create(ctx, env); err != nil {
		t.Fatalf("env Create: %v", err)
	}

	repo := storage.NewSecretWraps(pool)
	w := &storage.SecretWrap{
		// No RequestID — a direct_reveal wrap is parent-less
		EnvironmentID:     &env.ID,
		IssuedVia:         storage.WrapIssuedViaDirectReveal,
		KeyName:           "API_KEY",
		EncryptedValue:    []byte("ciphertext"),
		Nonce:             []byte("aaaaaaaaaaaa"),
		DataKeyCiphertext: []byte("dek-cipher"),
		KMSKeyID:          "local:test",
		ContentHash:       []byte("hash"),
		ByteLength:        42,
		ExpiresAt:         time.Now().Add(1 * time.Hour),
	}
	if err := repo.Create(ctx, w); err != nil {
		t.Fatalf("Create wrap: %v", err)
	}
	got, err := repo.Get(ctx, w.ID)
	if err != nil {
		t.Fatalf("Get wrap: %v", err)
	}
	if got.IssuedVia != storage.WrapIssuedViaDirectReveal {
		t.Errorf("issued_via: got %q want direct_reveal", got.IssuedVia)
	}
	if got.EnvironmentID == nil || *got.EnvironmentID != env.ID {
		t.Errorf("EnvironmentID: got %v want %v", got.EnvironmentID, env.ID)
	}
	if got.RequestID != nil {
		t.Errorf("RequestID: got %v want nil for direct_reveal", got.RequestID)
	}
}

func TestSecretWrap_IssuedViaCheckRejectsUnknown(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()

	// Direct INSERT with a value outside the CHECK should be rejected.
	_, err := pool.Exec(ctx, `
		INSERT INTO secret_wraps
		  (request_id, key_name, encrypted_value, nonce, data_key_ciphertext,
		   kms_key_id, algorithm, content_hash, byte_length, expires_at, issued_via)
		VALUES (NULL, 'k', '\x00', '\x00', '\x00', 'local:test', 'AES-256-GCM', '\x00', 1, now() + interval '1 hour', 'bogus')`)
	if err == nil {
		t.Fatal("expected CHECK violation on issued_via='bogus'")
	}
}

func TestProjectSecret_EnvironmentIDRoundtrip(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()

	projectID := makeProject(t, pool, "ps-env-id")
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	if err := envRepo.Create(ctx, env); err != nil {
		t.Fatalf("env Create: %v", err)
	}

	// Need a secret row to bind. Insert one directly.
	secretID := uuid.New()
	_, err := pool.Exec(ctx, `
		INSERT INTO secrets (id, cluster_name, provider_type, secret_ref, status, last_seen_at)
		VALUES ($1, 'test', 'vault', 'billing/uat/db', 'present', now())`,
		secretID,
	)
	if err != nil {
		t.Fatalf("insert secret: %v", err)
	}

	repo := storage.NewProjectSecrets(pool)
	b := &storage.ProjectSecret{
		ProjectID:     projectID,
		SecretID:      secretID,
		EnvironmentID: &env.ID,
		AllowedKeys:   nil,
		AllowedOps:    []string{"read"},
		CreatedBy:     "admin@example.com",
	}
	if err := repo.Bind(ctx, b); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	got, err := repo.Get(ctx, projectID, secretID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.EnvironmentID == nil || *got.EnvironmentID != env.ID {
		t.Errorf("EnvironmentID: got %v want %v", got.EnvironmentID, env.ID)
	}
}

func TestEnvironments_GetByProjectAndName(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()

	projectID := makeProject(t, pool, "env-by-name")
	repo := storage.NewEnvironments(pool)
	want := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	if err := repo.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByProjectAndName(ctx, projectID, "uat")
	if err != nil {
		t.Fatalf("GetByProjectAndName: %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("ID: got %v want %v", got.ID, want.ID)
	}
	if got.Kind != storage.EnvironmentKindNonProd {
		t.Errorf("Kind: got %q want non_prod", got.Kind)
	}

	// Miss → ErrNotFound.
	if _, err := repo.GetByProjectAndName(ctx, projectID, "missing"); err == nil {
		t.Error("expected ErrNotFound for missing env name")
	}
}
