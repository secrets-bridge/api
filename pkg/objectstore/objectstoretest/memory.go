// Package objectstoretest provides an in-memory objectstore.Store for
// tests, with switches to make each operation fail.
package objectstoretest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"sync"

	"github.com/secrets-bridge/api/pkg/objectstore"
)

// ErrInjected is the error returned by an operation switched to fail.
var ErrInjected = errors.New("objectstoretest: injected failure")

// Memory is an in-memory Store. The Fail* fields make the matching
// operation return ErrInjected; change them with Set so a concurrent
// request handler sees the change safely.
type Memory struct {
	mu      sync.Mutex
	objects map[string]memObject

	FailPut    bool
	FailGet    bool
	FailHead   bool
	FailDelete bool

	// Puts counts successful Put calls.
	Puts int
}

type memObject struct {
	data        []byte
	contentType string
}

// Set runs fn under the store's lock, for flipping the Fail* switches.
func (m *Memory) Set(fn func(m *Memory)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(m)
}

// NewMemory returns an empty Memory store.
func NewMemory() *Memory { return &Memory{objects: map[string]memObject{}} }

var _ objectstore.Store = (*Memory)(nil)

// Put stores a copy of body.
func (m *Memory) Put(_ context.Context, key string, body io.ReadSeeker, size int64, contentType string) error {
	b, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(b)) != size {
		return errors.New("objectstoretest: size does not match body")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailPut {
		return ErrInjected
	}
	m.objects[key] = memObject{data: b, contentType: contentType}
	m.Puts++
	return nil
}

// Get returns a reader over a copy of the object.
func (m *Memory) Get(_ context.Context, key string) (*objectstore.Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailGet {
		return nil, ErrInjected
	}
	o, ok := m.objects[key]
	if !ok {
		return nil, objectstore.ErrNotFound
	}
	return &objectstore.Object{
		Body:        io.NopCloser(bytes.NewReader(bytes.Clone(o.data))),
		Size:        int64(len(o.data)),
		ContentType: o.contentType,
	}, nil
}

// Head returns the object's size and type.
func (m *Memory) Head(_ context.Context, key string) (*objectstore.Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailHead {
		return nil, ErrInjected
	}
	o, ok := m.objects[key]
	if !ok {
		return nil, objectstore.ErrNotFound
	}
	return &objectstore.Info{Size: int64(len(o.data)), ContentType: o.contentType}, nil
}

// Delete removes the object; a missing key is not an error.
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailDelete {
		return ErrInjected
	}
	delete(m.objects, key)
	return nil
}

// Keys lists the stored keys in order.
func (m *Memory) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.objects))
	for k := range m.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Bytes returns a copy of the object at key, or nil.
func (m *Memory) Bytes(key string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objects[key]
	if !ok {
		return nil
	}
	return bytes.Clone(o.data)
}
