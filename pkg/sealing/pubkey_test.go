package sealing

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The low-order X25519 points (the libsodium blocklist), plus the same
// with the top bit set, which X25519 ignores.
var lowOrderPoints = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func TestValidatePublicKey_RefusesLowOrderAndAllZero(t *testing.T) {
	for _, h := range lowOrderPoints {
		raw, _ := hex.DecodeString(h)
		if err := ValidatePublicKey(raw); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("%s accepted", h)
		}
	}
}

func TestValidatePublicKey_LengthAndGoodKey(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		if ValidatePublicKey(make([]byte, n)) == nil {
			t.Errorf("%d-byte key accepted", n)
		}
	}
	pub, _, err := GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicKey(pub); err != nil {
		t.Fatalf("good key refused: %v", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := GenerateRecipientKey()
	b64 := base64.StdEncoding.EncodeToString(pub)
	if _, err := ParsePublicKey(b64, "x25519"); err != nil {
		t.Fatalf("good key: %v", err)
	}
	for name, c := range map[string][2]string{
		"algorithm":   {b64, "ed25519"},
		"url base64":  {base64.RawURLEncoding.EncodeToString(pub), "x25519"},
		"not base64":  {"***", "x25519"},
		"zero":        {base64.StdEncoding.EncodeToString(make([]byte, 32)), "x25519"},
		"trailing nl": {b64 + "\n", "x25519"},
	} {
		if _, err := ParsePublicKey(c[0], c[1]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFingerprint(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 9 // the base point
	fp := Fingerprint(raw)
	// sha256 of the 32 raw bytes, lowercase hex
	if fp != "sha256:"+strings.ToLower(fp[7:]) || len(fp) != 71 || !IsFingerprint(fp) {
		t.Fatalf("fingerprint %q", fp)
	}
	for _, bad := range []string{"", "sha256:", fp[:70], strings.ToUpper(fp), "sha512:" + fp[7:], fp + "0"} {
		if IsFingerprint(bad) {
			t.Errorf("IsFingerprint(%q)", bad)
		}
	}
}

// One point, one encoding: bit 255 set, or a value of p or more, is
// refused, so a key cannot be rotated to another encoding of itself and
// get a second fingerprint.
func TestValidatePublicKey_RefusesNonCanonical(t *testing.T) {
	pub, _, err := GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	high := append([]byte(nil), pub...)
	high[31] |= 0x80
	if ValidatePublicKey(high) == nil {
		t.Fatal("a key with bit 255 set was accepted")
	}
	if Fingerprint(high) == Fingerprint(pub) {
		t.Fatal("the two encodings share a fingerprint, the test proves nothing")
	}
	// 9 + p encodes the base point u = 9; p - 2 is the largest canonical
	// value that is not of low order.
	for name, c := range map[string]struct {
		hex string
		ok  bool
	}{
		"u=9":       {"0900000000000000000000000000000000000000000000000000000000000000", true},
		"9+p":       {"f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false},
		"p-2":       {"ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", true},
		"p+18":      {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false},
		"u=9 high":  {"0900000000000000000000000000000000000000000000000000000000000080", false},
		"p-2 bytes": {"ebfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffff7f", true},
	} {
		raw, _ := hex.DecodeString(c.hex)
		if err := ValidatePublicKey(raw); (err == nil) != c.ok {
			t.Errorf("%s: err %v, want accepted=%v", name, err, c.ok)
		}
	}
}
