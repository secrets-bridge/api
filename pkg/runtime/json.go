package runtime

import (
	"bytes"
	"encoding/json"
)

// jsonEncode is the package's single point of contact with the
// stdlib JSON encoder so a future swap (jsoniter, sonic, msgpack) is
// a one-line change.
func jsonEncode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Trim the trailing newline that json.Encoder appends.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// jsonDecode is the matching consumer of jsonEncode's output.
func jsonDecode(raw []byte, dst any) error {
	return json.Unmarshal(raw, dst)
}
