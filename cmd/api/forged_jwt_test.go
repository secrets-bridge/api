package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// forgedLoginJWT returns a token in the exact format /auth/login issued
// before M1 (api#191): HS256 over the header {"alg":"HS256","typ":"JWT"}
// and the iss/sub/iat/exp claims, signed with key. The api has no
// signer any more, and this one lives in a _test.go file so it never
// ships; tests use it to show a correctly signed token is not a
// credential.
func forgedLoginJWT(t *testing.T, key []byte, sub string) string {
	t.Helper()
	now := time.Now().UTC()
	claims, err := json.Marshal(map[string]any{
		"iss": "secrets-bridge", "sub": sub, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	input := enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc(claims)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return input + "." + enc(mac.Sum(nil))
}
