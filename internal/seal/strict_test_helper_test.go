package seal

import (
	"bytes"
	"encoding/json"
)

// newStrictDecoderForTest exposes the same DisallowUnknownFields decoder used
// in Open, so the unknown-field guard can be tested without re-sealing.
func newStrictDecoderForTest(payload []byte) *json.Decoder {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	return dec
}
