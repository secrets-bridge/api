package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image/png"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/objectstore"
	"github.com/secrets-bridge/api/pkg/objectstore/objectstoretest"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Unit tests for the object-storage paths of LogoService with a fake
// Store and a fake metadata repository: ordering of object and row
// writes, cleanup on failure, reads, the unconfigured state and the
// backfill.

type fakeLogoRepo struct {
	mu         sync.Mutex
	rows       map[storage.LogoKind]map[uuid.UUID]storage.Logo
	failUpsert bool
	failMove   bool
	upserts    int
}

func newFakeLogoRepo() *fakeLogoRepo {
	return &fakeLogoRepo{rows: map[storage.LogoKind]map[uuid.UUID]storage.Logo{
		storage.LogoKindProject: {}, storage.LogoKindTeam: {},
	}}
}

var errRowWrite = errors.New("fake: row write failed")

func (r *fakeLogoRepo) Get(_ context.Context, kind storage.LogoKind, id uuid.UUID) (*storage.Logo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.rows[kind][id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return &l, nil
}

func (r *fakeLogoRepo) Upsert(_ context.Context, kind storage.LogoKind, l *storage.Logo) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failUpsert {
		return "", errRowWrite
	}
	r.upserts++
	prev := r.rows[kind][l.EntityID].ObjectKey
	row := *l
	row.PNG = nil
	r.rows[kind][l.EntityID] = row
	return prev, nil
}

func (r *fakeLogoRepo) Delete(_ context.Context, kind storage.LogoKind, id uuid.UUID) (*storage.Logo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.rows[kind][id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	delete(r.rows[kind], id)
	l.PNG = nil
	return &l, nil
}

func (r *fakeLogoRepo) Versions(context.Context, storage.LogoKind, []uuid.UUID) (map[uuid.UUID]string, error) {
	return map[uuid.UUID]string{}, nil
}

func (r *fakeLogoRepo) ListInline(_ context.Context, kind storage.LogoKind, after uuid.UUID, limit int) ([]*storage.Logo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*storage.Logo
	for id, l := range r.rows[kind] {
		if l.PNG != nil && strings.Compare(id.String(), after.String()) > 0 {
			l := l
			out = append(out, &l)
		}
	}
	// Order by id like the SQL does.
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j].EntityID.String() < out[i].EntityID.String() {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *fakeLogoRepo) MoveToObject(_ context.Context, kind storage.LogoKind, id uuid.UUID, sha, key string, n int) (bool, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failMove {
		return false, "", errRowWrite
	}
	l, ok := r.rows[kind][id]
	if !ok {
		return false, "", nil
	}
	if l.PNG == nil || l.SHA256 != sha {
		return false, l.ObjectKey, nil
	}
	prev := l.ObjectKey
	l.PNG, l.ObjectKey, l.ByteLength = nil, key, n
	r.rows[kind][id] = l
	return true, prev, nil
}

func (r *fakeLogoRepo) CountInline(context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, m := range r.rows {
		for _, l := range m {
			if l.PNG != nil {
				n++
			}
		}
	}
	return n, nil
}

func (r *fakeLogoRepo) row(kind storage.LogoKind, id uuid.UUID) (storage.Logo, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.rows[kind][id]
	return l, ok
}

type fakeProjects struct{ storage.ProjectRepository }

func (fakeProjects) Get(_ context.Context, id uuid.UUID) (*storage.Project, error) {
	return &storage.Project{ID: id}, nil
}

type fakeTeams struct{ storage.TeamRepository }

func (fakeTeams) Get(_ context.Context, id uuid.UUID) (*storage.Team, error) {
	return &storage.Team{ID: id}, nil
}

type fakeAudit struct {
	storage.AuditEventRepository
	mu     sync.Mutex
	events []*storage.AuditEvent
}

func (a *fakeAudit) Append(_ context.Context, e *storage.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

type logoHarness struct {
	svc   *LogoService
	repo  *fakeLogoRepo
	store *objectstoretest.Memory
	audit *fakeAudit
}

func newLogoHarness(t *testing.T) *logoHarness {
	t.Helper()
	h := &logoHarness{repo: newFakeLogoRepo(), store: objectstoretest.NewMemory(), audit: &fakeAudit{}}
	h.svc = NewLogoService(h.repo, fakeProjects{}, fakeTeams{}, h.audit).
		WithStore(h.store, objectstore.Config{Bucket: "example-bucket", Prefix: "sb"})
	return h
}

func pngUpload(t *testing.T, w, h int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, gradient(w, h)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func readAllClose(t *testing.T, rc io.ReadCloser) []byte {
	t.Helper()
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLogoStore_PutWritesObjectThenRow(t *testing.T) {
	h := newLogoHarness(t)
	id := uuid.New()
	version, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", pngUpload(t, 40, 40), "user-1")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	row, ok := h.repo.row(storage.LogoKindProject, id)
	if !ok {
		t.Fatal("no row")
	}
	wantKey := "sb/logos/project/" + id.String() + "/" + row.SHA256 + ".png"
	if row.ObjectKey != wantKey || row.PNG != nil {
		t.Fatalf("row key %q (png %d bytes), want %q and no bytes", row.ObjectKey, len(row.PNG), wantKey)
	}
	obj := h.store.Bytes(wantKey)
	sum := sha256.Sum256(obj)
	if hex.EncodeToString(sum[:]) != row.SHA256 || row.ByteLength != len(obj) || version != row.SHA256[:12] {
		t.Fatalf("object digest/size/version mismatch: %d bytes, row %+v, version %s", len(obj), row, version)
	}

	// Read it back through Open.
	rc, size, err := h.svc.Open(t.Context(), storage.LogoKindProject, &row)
	if err != nil || size != int64(len(obj)) || !bytes.Equal(readAllClose(t, rc), obj) {
		t.Fatalf("Open: %v size %d", err, size)
	}
}

func TestLogoStore_ObjectWriteFailsLeavesRowAlone(t *testing.T) {
	h := newLogoHarness(t)
	id := uuid.New()
	if _, err := h.svc.Put(t.Context(), storage.LogoKindTeam, id, "image/png", pngUpload(t, 32, 32), "u"); err != nil {
		t.Fatal(err)
	}
	before, _ := h.repo.row(storage.LogoKindTeam, id)
	h.store.Set(func(m *objectstoretest.Memory) { m.FailPut = true })
	_, err := h.svc.Put(t.Context(), storage.LogoKindTeam, id, "image/png", pngUpload(t, 48, 48), "u")
	if !errors.Is(err, ErrLogoStorageFailed) {
		t.Fatalf("Put with failing store = %v, want ErrLogoStorageFailed", err)
	}
	after, _ := h.repo.row(storage.LogoKindTeam, id)
	if after.ObjectKey != before.ObjectKey || after.SHA256 != before.SHA256 || h.repo.upserts != 1 {
		t.Fatalf("row changed after a failed object write: %+v -> %+v (%d upserts)", before, after, h.repo.upserts)
	}
	if len(h.store.Keys()) != 1 || h.store.Bytes(before.ObjectKey) == nil {
		t.Fatalf("the current object should be untouched: %v", h.store.Keys())
	}
	if len(h.audit.events) != 1 {
		t.Fatalf("a failed write was audited: %d events", len(h.audit.events))
	}
}

func TestLogoStore_RowWriteFailsRemovesNewObject(t *testing.T) {
	h := newLogoHarness(t)
	id := uuid.New()
	h.repo.failUpsert = true
	_, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", pngUpload(t, 32, 32), "u")
	if !errors.Is(err, errRowWrite) {
		t.Fatalf("Put = %v, want the row error", err)
	}
	if keys := h.store.Keys(); len(keys) != 0 {
		t.Fatalf("object left behind after the row write failed: %v", keys)
	}
}

// Re-uploading the same image maps to the same content-addressed key.
// If the row write then fails, the object must stay: the existing row
// still points at it.
func TestLogoStore_RowWriteFailsKeepsObjectTheRowUses(t *testing.T) {
	h := newLogoHarness(t)
	id := uuid.New()
	img := pngUpload(t, 32, 32)
	if _, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", img, "u"); err != nil {
		t.Fatal(err)
	}
	row, _ := h.repo.row(storage.LogoKindProject, id)
	h.repo.failUpsert = true
	if _, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", img, "u"); err == nil {
		t.Fatal("want the row error")
	}
	if h.store.Bytes(row.ObjectKey) == nil {
		t.Fatal("cleanup removed the object the current row points at")
	}
	if h.store.Puts != 1 {
		t.Fatalf("identical image written %d times, want once (content-addressed key)", h.store.Puts)
	}
}

func TestLogoStore_ReplaceRemovesOldObjectAfterRow(t *testing.T) {
	h := newLogoHarness(t)
	id := uuid.New()
	if _, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", pngUpload(t, 32, 32), "u"); err != nil {
		t.Fatal(err)
	}
	first, _ := h.repo.row(storage.LogoKindProject, id)
	if _, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", pngUpload(t, 64, 64), "u"); err != nil {
		t.Fatal(err)
	}
	second, _ := h.repo.row(storage.LogoKindProject, id)
	if first.ObjectKey == second.ObjectKey {
		t.Fatal("different images got the same key")
	}
	if keys := h.store.Keys(); len(keys) != 1 || keys[0] != second.ObjectKey {
		t.Fatalf("keys after replace = %v, want only %s", keys, second.ObjectKey)
	}
}

// A failed delete of the old object does not fail the upload: the row
// already points at the new image, the old object is an orphan.
func TestLogoStore_OldObjectDeleteFailureIsNotFatal(t *testing.T) {
	h := newLogoHarness(t)
	id := uuid.New()
	if _, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", pngUpload(t, 32, 32), "u"); err != nil {
		t.Fatal(err)
	}
	h.store.Set(func(m *objectstoretest.Memory) { m.FailDelete = true })
	if _, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", pngUpload(t, 64, 64), "u"); err != nil {
		t.Fatalf("Put = %v; a failed cleanup must not fail the write", err)
	}
	if len(h.store.Keys()) != 2 {
		t.Fatalf("keys = %v, want new object plus the orphan", h.store.Keys())
	}
}

func TestLogoStore_DeleteRemovesRowThenObject(t *testing.T) {
	h := newLogoHarness(t)
	id := uuid.New()
	if _, err := h.svc.Put(t.Context(), storage.LogoKindTeam, id, "image/png", pngUpload(t, 32, 32), "u"); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Delete(t.Context(), storage.LogoKindTeam, id, "u"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.repo.row(storage.LogoKindTeam, id); ok || len(h.store.Keys()) != 0 {
		t.Fatalf("after delete: row present %v, keys %v", ok, h.store.Keys())
	}
	if err := h.svc.Delete(t.Context(), storage.LogoKindTeam, id, "u"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestLogoStore_OpenMissingObjectIsNotFound(t *testing.T) {
	h := newLogoHarness(t)
	l := &storage.Logo{EntityID: uuid.New(), ObjectKey: "sb/logos/project/x/y.png", SHA256: "y"}
	if _, _, err := h.svc.Open(t.Context(), storage.LogoKindProject, l); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Open missing object = %v, want storage.ErrNotFound", err)
	}
	h.store.Set(func(m *objectstoretest.Memory) { m.FailGet = true })
	if _, _, err := h.svc.Open(t.Context(), storage.LogoKindProject, l); !errors.Is(err, ErrLogoStorageFailed) {
		t.Fatalf("Open with failing store = %v, want ErrLogoStorageFailed", err)
	}
}

// A row from before the move still has its bytes inline; Open serves
// them without touching the store, and inline bytes win over a key.
func TestLogoStore_OpenInlineRow(t *testing.T) {
	h := newLogoHarness(t)
	h.store.Set(func(m *objectstoretest.Memory) { m.FailGet = true })
	l := &storage.Logo{EntityID: uuid.New(), PNG: []byte("inline"), ObjectKey: "stale"}
	rc, size, err := h.svc.Open(t.Context(), storage.LogoKindProject, l)
	if err != nil || size != 6 || string(readAllClose(t, rc)) != "inline" {
		t.Fatalf("Open inline: %v %d", err, size)
	}
}

func TestLogoStore_UnconfiguredRefusesWrites(t *testing.T) {
	repo := newFakeLogoRepo()
	svc := NewLogoService(repo, fakeProjects{}, fakeTeams{}, &fakeAudit{})
	id := uuid.New()
	if _, err := svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", pngUpload(t, 32, 32), "u"); !errors.Is(err, ErrLogoStorageUnavailable) {
		t.Fatalf("Put = %v, want ErrLogoStorageUnavailable", err)
	}
	if err := svc.Delete(t.Context(), storage.LogoKindProject, id, "u"); !errors.Is(err, ErrLogoStorageUnavailable) {
		t.Fatalf("Delete = %v, want ErrLogoStorageUnavailable", err)
	}
	if repo.upserts != 0 {
		t.Fatal("an unconfigured service wrote a row")
	}
	// Inline rows are still readable; object rows can't be.
	rc, _, err := svc.Open(t.Context(), storage.LogoKindProject, &storage.Logo{PNG: []byte("x")})
	if err != nil {
		t.Fatalf("Open inline without a store: %v", err)
	}
	_ = rc.Close()
	if _, _, err := svc.Open(t.Context(), storage.LogoKindProject, &storage.Logo{ObjectKey: "k"}); !errors.Is(err, ErrLogoStorageUnavailable) {
		t.Fatalf("Open object without a store = %v", err)
	}
	if _, err := svc.BackfillObjects(t.Context()); !errors.Is(err, ErrLogoStorageUnavailable) {
		t.Fatalf("Backfill without a store = %v", err)
	}
}

func TestLogoStore_AuditHasNoBytesOrLocation(t *testing.T) {
	h := newLogoHarness(t)
	id := uuid.New()
	if _, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", pngUpload(t, 32, 32), "u"); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Delete(t.Context(), storage.LogoKindProject, id, "u"); err != nil {
		t.Fatal(err)
	}
	if len(h.audit.events) != 2 {
		t.Fatalf("%d audit events", len(h.audit.events))
	}
	for _, e := range h.audit.events {
		b, _ := json.Marshal(e.Metadata)
		if len(e.Metadata) != 4 || strings.Contains(string(b), "logos/") || strings.Contains(string(b), "example-bucket") || strings.Contains(string(b), "http") {
			t.Errorf("%s metadata %s: want byte_length, sha256, width, height only", e.Action, b)
		}
		if e.Metadata["byte_length"].(int) <= 0 {
			t.Errorf("%s: byte_length %v", e.Action, e.Metadata["byte_length"])
		}
	}
}

func inlineRow(t *testing.T, w int) storage.Logo {
	t.Helper()
	img := pngUpload(t, w, w)
	sum := sha256.Sum256(img)
	return storage.Logo{EntityID: uuid.New(), PNG: img, ByteLength: len(img), SHA256: hex.EncodeToString(sum[:]), Width: w, Height: w, UpdatedBy: "old"}
}

func TestLogoBackfill_MovesInlineRowsAndIsIdempotent(t *testing.T) {
	h := newLogoHarness(t)
	var ids []uuid.UUID
	for i := range 250 { // more than one page
		l := inlineRow(t, 16+i%8)
		h.repo.rows[storage.LogoKindProject][l.EntityID] = l
		ids = append(ids, l.EntityID)
	}
	team := inlineRow(t, 20)
	h.repo.rows[storage.LogoKindTeam][team.EntityID] = team
	// Bytes that don't match the recorded digest stay inline.
	bad := inlineRow(t, 18)
	bad.SHA256 = strings.Repeat("0", 64)
	h.repo.rows[storage.LogoKindTeam][bad.EntityID] = bad

	res, err := h.svc.BackfillObjects(t.Context())
	if err != nil || res.Moved != 251 || res.Skipped != 1 || res.Failed != 0 {
		t.Fatalf("first run = %+v, %v", res, err)
	}
	for _, id := range ids {
		row, _ := h.repo.row(storage.LogoKindProject, id)
		if row.PNG != nil || h.store.Bytes(row.ObjectKey) == nil || row.ByteLength == 0 {
			t.Fatalf("row %s not moved: %+v", id, row)
		}
		rc, _, err := h.svc.Open(t.Context(), storage.LogoKindProject, &row)
		if err != nil {
			t.Fatal(err)
		}
		got := readAllClose(t, rc)
		sum := sha256.Sum256(got)
		if hex.EncodeToString(sum[:]) != row.SHA256 {
			t.Fatal("moved object does not match the row digest")
		}
	}
	if n, _ := h.repo.CountInline(t.Context()); n != 1 {
		t.Fatalf("inline rows left = %d, want only the mismatched one", n)
	}
	puts := h.store.Puts
	res, err = h.svc.BackfillObjects(t.Context())
	if err != nil || res.Moved != 0 || res.Failed != 0 || res.Skipped != 1 || h.store.Puts != puts {
		t.Fatalf("second run = %+v, %v, %d new puts; want nothing moved", res, err, h.store.Puts-puts)
	}
	if h.audit.events != nil {
		t.Fatal("the backfill wrote audit events")
	}
}

func TestLogoBackfill_FailuresLeaveRowsInlineAndRetry(t *testing.T) {
	h := newLogoHarness(t)
	l := inlineRow(t, 24)
	h.repo.rows[storage.LogoKindProject][l.EntityID] = l

	h.store.Set(func(m *objectstoretest.Memory) { m.FailPut = true })
	if res, err := h.svc.BackfillObjects(t.Context()); err != nil || res.Failed != 1 {
		t.Fatalf("store failing: %+v %v", res, err)
	}
	h.store.Set(func(m *objectstoretest.Memory) { m.FailPut = false })
	h.repo.failMove = true
	if res, err := h.svc.BackfillObjects(t.Context()); err != nil || res.Failed != 1 {
		t.Fatalf("row failing: %+v %v", res, err)
	}
	if row, _ := h.repo.row(storage.LogoKindProject, l.EntityID); row.PNG == nil {
		t.Fatal("row lost its bytes after a failed move")
	}
	h.repo.failMove = false
	if res, err := h.svc.BackfillObjects(t.Context()); err != nil || res.Moved != 1 {
		t.Fatalf("retry: %+v %v", res, err)
	}
	if keys := h.store.Keys(); len(keys) != 1 {
		t.Fatalf("keys = %v", keys)
	}
}

// A replica on the old version wrote png over a row that already had an
// object: the backfill moves the new bytes and removes the stale object.
func TestLogoBackfill_RemovesStaleObjectFromOldReplicaWrite(t *testing.T) {
	h := newLogoHarness(t)
	id := uuid.New()
	if _, err := h.svc.Put(t.Context(), storage.LogoKindProject, id, "image/png", pngUpload(t, 32, 32), "u"); err != nil {
		t.Fatal(err)
	}
	stale, _ := h.repo.row(storage.LogoKindProject, id)
	newer := inlineRow(t, 40)
	newer.EntityID, newer.ObjectKey = id, stale.ObjectKey
	h.repo.rows[storage.LogoKindProject][id] = newer

	res, err := h.svc.BackfillObjects(t.Context())
	if err != nil || res.Moved != 1 {
		t.Fatalf("backfill = %+v %v", res, err)
	}
	row, _ := h.repo.row(storage.LogoKindProject, id)
	if keys := h.store.Keys(); len(keys) != 1 || keys[0] != row.ObjectKey || row.ObjectKey == stale.ObjectKey {
		t.Fatalf("keys %v, row key %s, stale %s", keys, row.ObjectKey, stale.ObjectKey)
	}
}
