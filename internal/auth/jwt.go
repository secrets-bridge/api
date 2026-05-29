// Tiny HS256 JWT signer / verifier. Built from stdlib (crypto/hmac +
// crypto/sha256 + encoding/base64 + encoding/json) — adding a JWT
// library for the ~80 lines below would drag transitive deps the
// minimal-login slice doesn't need.
//
// The OIDC swap (api#26) replaces this with a verified RS256 / ES256
// flow against the IdP's JWKS endpoint. This file stays as the
// fallback for the local-admin login path when OIDC is off.
//
// Wire format: `<base64url(header)>.<base64url(payload)>.<base64url(sig)>`.
// Header is `{"alg":"HS256","typ":"JWT"}` — we never accept any other
// alg (defends against the well-known `alg=none` downgrade).
// Payload carries:
//   iss   "secrets-bridge"
//   sub   user_id (UUID string for local users; future: OIDC sub)
//   iat   issued-at unix seconds
//   exp   expires-at unix seconds
//   email best-effort display string (NOT used for identity gating)
//   name  display name (NOT used for identity gating)

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims is the JWT payload shape.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
}

// ErrInvalidToken is returned for any verification failure. We
// deliberately do NOT differentiate between "bad signature" / "expired"
// / "wrong alg" in the public error so an attacker can't probe.
var ErrInvalidToken = errors.New("auth: invalid token")

const (
	jwtHeaderHS256 = `{"alg":"HS256","typ":"JWT"}`
	jwtIssuer      = "secrets-bridge"
)

var jwtHeaderEncoded = base64.RawURLEncoding.EncodeToString([]byte(jwtHeaderHS256))

// Signer holds the HMAC secret. Construct once at boot via
// `NewSigner(secret)` and reuse — `SignToken` / `VerifyToken` are
// safe for concurrent use.
type Signer struct {
	secret []byte
}

// NewSigner returns a configured Signer. The secret MUST be at least
// 32 bytes of entropy (e.g. base64-decoded `crypto/rand` output);
// callers should validate length at the config boundary.
func NewSigner(secret []byte) *Signer {
	return &Signer{secret: secret}
}

// SignToken returns a signed JWT carrying the given claims. The
// caller fills `Subject` + optional `Email` / `Name`; `Issuer` and
// `IssuedAt` / `ExpiresAt` are stamped here.
func (s *Signer) SignToken(claims Claims, ttl time.Duration) (string, time.Time, error) {
	now := time.Now().UTC()
	expires := now.Add(ttl)
	claims.Issuer = jwtIssuer
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = expires.Unix()

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: marshal claims: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := jwtHeaderEncoded + "." + payloadEncoded

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigEncoded := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigEncoded, expires, nil
}

// VerifyToken validates signature + alg + expiry, returns the claims
// on success. Any failure returns `ErrInvalidToken` — never a
// disclosing error.
func (s *Signer) VerifyToken(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	header, payloadEnc, sigEnc := parts[0], parts[1], parts[2]

	// Header must be exactly the supported HS256 form. Comparing the
	// encoded string avoids any header-parsing fallibility (e.g. an
	// attacker substituting `alg=none`).
	if header != jwtHeaderEncoded {
		return nil, ErrInvalidToken
	}

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(header + "." + payloadEnc))
	expectedSig := mac.Sum(nil)

	gotSig, err := base64.RawURLEncoding.DecodeString(sigEnc)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if subtle.ConstantTimeCompare(expectedSig, gotSig) != 1 {
		return nil, ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadEnc)
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if claims.Issuer != jwtIssuer {
		return nil, ErrInvalidToken
	}
	if claims.Subject == "" {
		return nil, ErrInvalidToken
	}
	now := time.Now().UTC().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, ErrInvalidToken
	}
	if claims.IssuedAt > 0 && claims.IssuedAt > now+60 {
		// Clock skew tolerance: reject tokens minted more than 60s
		// in the future.
		return nil, ErrInvalidToken
	}
	return &claims, nil
}
