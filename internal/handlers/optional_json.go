package handlers

import (
	"bytes"
	"encoding/json"

	"github.com/google/uuid"
)

// Update bodies use pointer fields so an absent key keeps the stored
// value and a present key applies, including an explicit false or 0. A
// plain pointer can't tell an absent key from an explicit null, though,
// and for a few nullable columns null means something ("move this team
// to the root", "allow all keys"). These two types record presence for
// those columns. encoding/json calls UnmarshalJSON for a present key even
// when its value is null, and never for an absent one.

// optionalUUID is a nullable UUID field whose presence is tracked.
type optionalUUID struct {
	Set   bool       // the key was in the body
	Value *uuid.UUID // nil when the body sent null
}

func (o *optionalUUID) UnmarshalJSON(b []byte) error {
	o.Set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		o.Value = nil
		return nil
	}
	var id uuid.UUID
	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}
	o.Value = &id
	return nil
}

// optionalStrings is a nullable string list whose presence is tracked.
type optionalStrings struct {
	Set   bool     // the key was in the body
	Value []string // nil when the body sent null
}

func (o *optionalStrings) UnmarshalJSON(b []byte) error {
	o.Set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		o.Value = nil
		return nil
	}
	var v []string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if v == nil {
		v = []string{}
	}
	o.Value = v
	return nil
}
