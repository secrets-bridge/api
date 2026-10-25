package main

// One X25519 point, one encoding (api#328 review): a public key with bit
// 255 set, or a value of p or more, is another encoding of a point the
// curve also reaches canonically. Accepting it gave one key up to four
// fingerprints, so a "rotation" to the same key could pass as a new one.

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// highBit is pub with bit 255 set: the same point to X25519.
func highBit(pub []byte) []byte {
	out := append([]byte(nil), pub...)
	out[31] |= 0x80
	return out
}

func TestLive_EnrollV2_RefusesNonCanonicalKeys(t *testing.T) {
	f := newV2Fixture(t)

	// Enroll: the challenge for a high-bit key is refused, and the token
	// stays usable for a canonical key.
	tok := f.token(t)
	c := newEnrollClient(t)
	body := c.challengeBody(tok)
	body["public_key"] = base64.StdEncoding.EncodeToString(highBit(c.pub))
	code, raw := f.l.call(t, http.MethodPost, "/api/v1/agents/enroll/challenge", "", body)
	if code != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_public_key") {
		t.Fatalf("enroll challenge with bit 255 set = %d %s; want 400 invalid_public_key", code, raw)
	}
	a := f.enroll(t, tok, "v2-canonical")

	// Rotation: another encoding of the agent's own key is refused, and
	// the bound key and its version stay as they were.
	admin := uuid.New()
	adminHdr := map[string]string{"Cookie": f.l.sessionFor(t, admin, "v2-canonical-admin@example.com")}
	f.l.addGrant(t, admin.String(), []string{"agent.mint"}, `{}`)
	code, raw = f.l.callAs(t, http.MethodPost, "/api/v1/admin/agents/"+a.id+"/key-rotation", adminHdr, nil)
	if code != http.StatusCreated {
		t.Fatalf("rotation token = %d %s", code, raw)
	}
	var issued struct {
		RotationToken string `json:"rotation_token"`
	}
	mustJSON(t, raw, &issued)
	ch := a.c.challengeBody("")
	delete(ch, "enrollment_token")
	ch["rotation_token"] = issued.RotationToken
	ch["public_key"] = base64.StdEncoding.EncodeToString(highBit(a.c.pub))
	code, raw = f.l.callAs(t, http.MethodPost, "/api/v1/agents/"+a.id+"/key-rotation/challenge",
		map[string]string{"X-Agent-Secret": a.secret}, ch)
	if code != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_public_key") {
		t.Fatalf("rotation challenge to the same key with bit 255 set = %d %s; want 400 invalid_public_key", code, raw)
	}
	var version int
	var stored []byte
	if err := f.l.pool.QueryRow(t.Context(), `SELECT public_key_version, public_key FROM agents WHERE id = $1`, a.id).Scan(&version, &stored); err != nil {
		t.Fatal(err)
	}
	if version != 1 || string(stored) != string(a.c.pub) {
		t.Fatalf("after the refused rotation: version %d, key changed %v; want version 1 and the enrolled key", version, string(stored) != string(a.c.pub))
	}
	if code, body := f.heartbeat(t, a, a.c.fingerprint()); code != http.StatusNoContent {
		t.Fatalf("heartbeat with the enrolled key = %d %s", code, body)
	}
}
