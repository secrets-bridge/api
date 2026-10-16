package auth

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// Grant scope keys. A user_roles.scope object may carry only these. Any
// other key is refused when a grant is written (API-N-06).
const (
	ScopeKeyProjectID       = "project_id"
	ScopeKeyTeamID          = "team_id"
	ScopeKeyEnvironment     = "environment"
	ScopeKeySecretRefPrefix = "secret_ref_prefix"
	ScopeKeyProviderType    = "provider_type"
)

// grantScopeKeys maps each allowed key to whether its value must be a
// UUID.
var grantScopeKeys = map[string]bool{
	ScopeKeyProjectID:       true,
	ScopeKeyTeamID:          true,
	ScopeKeyEnvironment:     false,
	ScopeKeySecretRefPrefix: false,
	ScopeKeyProviderType:    false,
}

// ErrInvalidGrantScope is returned by NormalizeGrantScope. The wrapped
// message names the offending key when it is one of ours, never the
// caller's value.
var ErrInvalidGrantScope = errors.New("invalid grant scope")

// NormalizeGrantScope validates a grant scope before it is stored and
// returns the copy to persist. An absent or empty scope is a global grant
// and stays empty.
//
// Rules: only the keys above; every value a non-empty string; project_id
// and team_id must parse as UUIDs and are stored in canonical form so the
// exact-match scope checks compare like with like.
//
// The guards treat an empty scope as global, so before this check a grant
// such as {"project_id":""} or {"team_id":123} quietly became global once
// the bad value was dropped at evaluation time.
func NormalizeGrantScope(in map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(in))
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		isID, known := grantScopeKeys[k]
		if !known {
			return nil, fmt.Errorf("%w: unsupported key (allowed: project_id, team_id, environment, secret_ref_prefix, provider_type)", ErrInvalidGrantScope)
		}
		s, ok := in[k].(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("%w: %s must be a non-empty string", ErrInvalidGrantScope, k)
		}
		if isID {
			id, err := uuid.Parse(s)
			if err != nil {
				return nil, fmt.Errorf("%w: %s must be a UUID", ErrInvalidGrantScope, k)
			}
			s = id.String()
		}
		out[k] = s
	}
	return out, nil
}

// grantScopeStrings converts a stored scope into the string form the
// guards evaluate. ok is false when any value is not a non-empty string.
//
// A malformed grant must cover nothing. The previous behaviour dropped the
// bad key and kept the rest, which widens the grant: {"project_id":""}
// collapsed to {} (global) and {"project_id":"","environment":"uat"} to
// {"environment":"uat"} (every project in uat).
func grantScopeStrings(in map[string]any) (map[string]string, bool) {
	out := make(map[string]string, len(in))
	for k, v := range in {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, false
		}
		out[k] = s
	}
	return out, true
}
