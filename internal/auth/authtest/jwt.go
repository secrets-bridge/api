// Package authtest forges the HS256 bearer tokens the api issued before
// M1 (api#191). It exists only so tests can prove such a token is no
// longer a credential; production code must not import it.
//
// Wire format: `<base64url(header)>.<base64url(payload)>.<base64url(sig)>`
// with header `{"alg":"HS256","typ":"JWT"}` and the claims below.
package authtest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Claims is the payload of the old login token.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
}

const (
	jwtHeaderHS256 = `{"alg":"HS256","typ":"JWT"}`
	jwtIssuer      = "secrets-bridge"
)

var jwtHeaderEncoded = base64.RawURLEncoding.EncodeToString([]byte(jwtHeaderHS256))

// Signer signs tokens with an HMAC secret.
type Signer struct {
	secret []byte
}

// NewSigner returns a Signer for secret.
func NewSigner(secret []byte) *Signer {
	return &Signer{secret: secret}
}

// SignToken returns a token carrying claims, valid for ttl, in the
// format the api used to hand out from login. Issuer and the times are
// stamped here.
func (s *Signer) SignToken(claims Claims, ttl time.Duration) (string, time.Time, error) {
	now := time.Now().UTC()
	expires := now.Add(ttl)
	claims.Issuer = jwtIssuer
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = expires.Unix()

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authtest: marshal claims: %w", err)
	}
	signingInput := jwtHeaderEncoded + "." + base64.RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), expires, nil
}
