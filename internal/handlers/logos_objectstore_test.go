package handlers_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/objectstore"
	"github.com/secrets-bridge/api/pkg/objectstore/objectstoretest"
)

// Logos in object storage (secrets-bridge/api#253): bytes leave
// Postgres, the HTTP contract stays the same, inline rows from before
// the move are served until the backfill moves them, and the failure
// paths answer without leaking detail.

func logoRow(t *testing.T, fx *logoFixture, table, column string, id uuid.UUID) (objectKey string, inline bool, sha string) {
	t.Helper()
	var key *string
	err := fx.pool.QueryRow(t.Context(),
		`SELECT object_key, png IS NOT NULL, sha256 FROM `+table+` WHERE `+column+` = $1`, id).Scan(&key, &inline, &sha)
	if err != nil {
		t.Fatalf("read %s row: %v", table, err)
	}
	if key != nil {
		objectKey = *key
	}
	return objectKey, inline, sha
}

func TestLogoObjects_PutStoresBytesOutsidePostgres(t *testing.T) {
	fx := bootstrapLogos(t)
	path := "/api/v1/teams/" + fx.team.String() + "/logo"
	if r := fx.do(t, http.MethodPut, path, fx.admin, "image/png", pngBytes(t, 40, 40), nil); r.status != http.StatusOK {
		t.Fatalf("PUT: %d %s", r.status, r.body)
	}
	key, inline, sha := logoRow(t, fx, "team_logos", "team_id", fx.team)
	if inline {
		t.Fatal("image bytes written to Postgres")
	}
	if !strings.HasSuffix(key, "logos/team/"+fx.team.String()+"/"+sha+".png") {
		t.Fatalf("object key %q does not follow <prefix>/logos/<kind>/<id>/<sha256>.png", key)
	}
	obj, err := fx.store.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("object not in the store: %v", err)
	}
	_ = obj.Body.Close()
	get := fx.do(t, http.MethodGet, path, fx.admin, "", nil, nil)
	sum := sha256.Sum256(get.body)
	if get.status != http.StatusOK || hex.EncodeToString(sum[:]) != sha || get.header.Get("Etag") != `"`+sha+`"` {
		t.Fatalf("GET: %d, etag %s", get.status, get.header.Get("Etag"))
	}

	// Replacing removes the old object once the row points at the new one.
	if r := fx.do(t, http.MethodPut, path, fx.admin, "image/png", pngBytes(t, 64, 64), nil); r.status != http.StatusOK {
		t.Fatalf("second PUT: %d", r.status)
	}
	newKey, _, _ := logoRow(t, fx, "team_logos", "team_id", fx.team)
	if newKey == key {
		t.Fatal("new image kept the old key")
	}
	if _, err := fx.store.Head(t.Context(), key); err == nil {
		t.Fatal("old object still in the store after replace")
	}
	// Delete removes the object too.
	if r := fx.do(t, http.MethodDelete, path, fx.admin, "", nil, nil); r.status != http.StatusNoContent {
		t.Fatalf("DELETE: %d", r.status)
	}
	if _, err := fx.store.Head(t.Context(), newKey); err == nil {
		t.Fatal("object still in the store after delete")
	}
}

func TestLogoObjects_MissingObjectIs404(t *testing.T) {
	fx := bootstrapLogos(t)
	path := "/api/v1/projects/" + fx.project.String() + "/logo"
	if r := fx.do(t, http.MethodPut, path, fx.admin, "image/png", pngBytes(t, 32, 32), nil); r.status != http.StatusOK {
		t.Fatalf("PUT: %d", r.status)
	}
	key, _, sha := logoRow(t, fx, "project_logos", "project_id", fx.project)
	if err := fx.store.Delete(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	r := fx.do(t, http.MethodGet, path, fx.admin, "", nil, nil)
	if r.status != http.StatusNotFound || bytes.Contains(r.body, []byte(key)) {
		t.Fatalf("GET with the object gone: %d %s, want 404 without the key", r.status, r.body)
	}
	// A conditional request still answers from the row alone.
	r = fx.do(t, http.MethodGet, path, fx.admin, "", nil, map[string]string{"If-None-Match": `"` + sha + `"`})
	if r.status != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", r.status)
	}
}

// A logo stored inline before 0040 is served with the same headers and
// ETag, then the backfill moves it; the response is byte-for-byte the
// same and a second run does nothing.
func TestLogoObjects_InlineRowServedThenBackfilled(t *testing.T) {
	fx := bootstrapLogos(t)
	img := pngBytes(t, 24, 24)
	sum := sha256.Sum256(img)
	sha := hex.EncodeToString(sum[:])
	if _, err := fx.pool.Exec(t.Context(), `INSERT INTO project_logos (project_id, png, sha256, width, height, updated_by)
		VALUES ($1, $2, $3, 24, 24, 'old')`, fx.project, img, sha); err != nil {
		t.Fatalf("seed inline logo: %v", err)
	}
	path := "/api/v1/projects/" + fx.project.String() + "/logo"
	check := func(stage string) {
		t.Helper()
		r := fx.do(t, http.MethodGet, path, fx.admin, "", nil, nil)
		if r.status != http.StatusOK || !bytes.Equal(r.body, img) {
			t.Fatalf("%s: GET %d (%d bytes)", stage, r.status, len(r.body))
		}
		want := map[string]string{
			"Content-Type":            "image/png",
			"Etag":                    `"` + sha + `"`,
			"X-Content-Type-Options":  "nosniff",
			"Content-Security-Policy": "default-src 'none'; sandbox",
			"Content-Disposition":     `inline; filename="logo.png"`,
			"Cache-Control":           "private, max-age=31536000, immutable",
		}
		for k, v := range want {
			if got := r.header.Get(k); got != v {
				t.Errorf("%s: header %s = %q, want %q", stage, k, got, v)
			}
		}
	}
	check("inline")

	res, err := fx.svc.BackfillObjects(t.Context())
	if err != nil || res.Moved != 1 || res.Failed != 0 {
		t.Fatalf("backfill = %+v, %v", res, err)
	}
	key, inline, _ := logoRow(t, fx, "project_logos", "project_id", fx.project)
	if inline || key == "" {
		t.Fatalf("after backfill: inline %v key %q", inline, key)
	}
	var left int
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM project_logos WHERE png IS NOT NULL`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("image bytes left in Postgres: %d %v", left, err)
	}
	check("moved")

	res, err = fx.svc.BackfillObjects(t.Context())
	if err != nil || res != (services.LogoBackfillResult{}) {
		t.Fatalf("second backfill = %+v, %v; want nothing to do", res, err)
	}
	var audits int
	_ = fx.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action LIKE '%.logo.%'`).Scan(&audits)
	if audits != 0 {
		t.Fatalf("backfill wrote %d audit events", audits)
	}
}

func TestLogoObjects_UnconfiguredRefusesWritesServesInline(t *testing.T) {
	fx := bootstrapLogosWith(t, nil, objectstore.Config{})
	path := "/api/v1/projects/" + fx.project.String() + "/logo"
	r := fx.do(t, http.MethodPut, path, fx.admin, "image/png", pngBytes(t, 32, 32), nil)
	if r.status != http.StatusServiceUnavailable || !strings.Contains(string(r.body), "logo storage is not configured") {
		t.Fatalf("PUT without object storage: %d %s", r.status, r.body)
	}
	var n int
	_ = fx.pool.QueryRow(t.Context(), `SELECT count(*) FROM project_logos`).Scan(&n)
	if n != 0 {
		t.Fatal("PUT without object storage stored a row")
	}
	img := pngBytes(t, 20, 20)
	sum := sha256.Sum256(img)
	if _, err := fx.pool.Exec(t.Context(), `INSERT INTO project_logos (project_id, png, sha256, width, height, updated_by)
		VALUES ($1, $2, $3, 20, 20, 'old')`, fx.project, img, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if r := fx.do(t, http.MethodGet, path, fx.admin, "", nil, nil); r.status != http.StatusOK || !bytes.Equal(r.body, img) {
		t.Fatalf("GET inline without object storage: %d", r.status)
	}
	if r := fx.do(t, http.MethodDelete, path, fx.admin, "", nil, nil); r.status != http.StatusServiceUnavailable {
		t.Fatalf("DELETE without object storage: %d", r.status)
	}
}

func TestLogoObjects_StoreFailureAnswers503WithoutDetail(t *testing.T) {
	mem := objectstoretest.NewMemory()
	fx := bootstrapLogosWith(t, mem, objectstore.Config{Bucket: "example-bucket"})
	path := "/api/v1/projects/" + fx.project.String() + "/logo"
	if r := fx.do(t, http.MethodPut, path, fx.admin, "image/png", pngBytes(t, 32, 32), nil); r.status != http.StatusOK {
		t.Fatalf("PUT: %d", r.status)
	}
	before, _, beforeSHA := logoRow(t, fx, "project_logos", "project_id", fx.project)

	mem.Set(func(m *objectstoretest.Memory) { m.FailPut = true })
	r := fx.do(t, http.MethodPut, path, fx.admin, "image/png", pngBytes(t, 48, 48), nil)
	if r.status != http.StatusServiceUnavailable || strings.Contains(string(r.body), objectstoretest.ErrInjected.Error()) {
		t.Fatalf("PUT with a failing store: %d %s", r.status, r.body)
	}
	after, _, afterSHA := logoRow(t, fx, "project_logos", "project_id", fx.project)
	if after != before || afterSHA != beforeSHA {
		t.Fatal("row changed after the object write failed")
	}

	mem.Set(func(m *objectstoretest.Memory) { m.FailPut, m.FailGet = false, true })
	r = fx.do(t, http.MethodGet, path, fx.admin, "", nil, nil)
	if r.status != http.StatusServiceUnavailable || strings.Contains(string(r.body), objectstoretest.ErrInjected.Error()) {
		t.Fatalf("GET with a failing store: %d %s", r.status, r.body)
	}
}

// When the row write fails after the object went in, the new object is
// removed again and the client gets a generic error.
func TestLogoObjects_RowWriteFailureCleansObject(t *testing.T) {
	mem := objectstoretest.NewMemory()
	fx := bootstrapLogosWith(t, mem, objectstore.Config{Bucket: "example-bucket"})
	// A trigger that refuses the logo row makes the row write fail after
	// the object write succeeded.
	ctx := t.Context()
	if _, err := fx.pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION test_fail_logo_write() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'row write refused for test'; END $$ LANGUAGE plpgsql;
		CREATE TRIGGER test_fail_logo_write BEFORE INSERT OR UPDATE ON project_logos
		FOR EACH ROW EXECUTE FUNCTION test_fail_logo_write();`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	t.Cleanup(func() {
		// t.Context() is already cancelled in cleanup.
		_, _ = fx.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS test_fail_logo_write ON project_logos; DROP FUNCTION IF EXISTS test_fail_logo_write();`)
	})
	r := fx.do(t, http.MethodPut, "/api/v1/projects/"+fx.project.String()+"/logo", fx.admin, "image/png", pngBytes(t, 32, 32), nil)
	if r.status != http.StatusInternalServerError || strings.Contains(string(r.body), "refused for test") {
		t.Fatalf("PUT with a failing row write: %d %s, want a generic 500", r.status, r.body)
	}
	if mem.Puts != 1 {
		t.Fatalf("object writes = %d, want 1 (object first)", mem.Puts)
	}
	if keys := mem.Keys(); len(keys) != 0 {
		t.Fatalf("object left behind after the row write failed: %v", keys)
	}
}
