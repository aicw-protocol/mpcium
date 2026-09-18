package types

import (
	"encoding/json"
	"testing"
)

// The legacy payload must stay byte-identical so signatures from initiators
// that do not send key_types keep verifying on upgraded nodes.
func TestGenerateKeyMessage_Raw_LegacyWithoutKeyTypes(t *testing.T) {
	m := &GenerateKeyMessage{WalletID: "w-1"}
	raw, err := m.Raw()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "w-1" {
		t.Fatalf("legacy raw = %q, want %q", raw, "w-1")
	}
}

// key_types must be bound into the signed payload: changing them must change
// Raw(), otherwise a relay could add/strip a family under a valid signature.
func TestGenerateKeyMessage_Raw_BindsKeyTypes(t *testing.T) {
	ed := &GenerateKeyMessage{WalletID: "w-1", KeyTypes: []KeyType{KeyTypeEd25519}}
	both := &GenerateKeyMessage{WalletID: "w-1", KeyTypes: []KeyType{KeyTypeEd25519, KeyTypeSecp256k1}}

	rawEd, _ := ed.Raw()
	rawBoth, _ := both.Raw()
	if string(rawEd) == "w-1" {
		t.Fatal("raw with key_types must differ from legacy payload")
	}
	if string(rawEd) == string(rawBoth) {
		t.Fatal("different key_types must produce different signed payloads")
	}
	if string(rawBoth) != "w-1|key_types=ed25519,secp256k1" {
		t.Fatalf("canonical raw = %q", rawBoth)
	}
}

// Wire format: key_types round-trips and is omitted when empty (so old nodes
// that ignore unknown fields see the exact legacy message).
func TestGenerateKeyMessage_JSONRoundTrip(t *testing.T) {
	legacy, _ := json.Marshal(&GenerateKeyMessage{WalletID: "w-1", Signature: []byte("s")})
	if string(legacy) != `{"wallet_id":"w-1","signature":"cw=="}` {
		t.Fatalf("legacy json = %s", legacy)
	}

	in := &GenerateKeyMessage{WalletID: "w-2", KeyTypes: []KeyType{KeyTypeSecp256k1}, Signature: []byte("s")}
	b, _ := json.Marshal(in)
	var out GenerateKeyMessage
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.KeyTypes) != 1 || out.KeyTypes[0] != KeyTypeSecp256k1 {
		t.Fatalf("round-trip key_types = %v", out.KeyTypes)
	}
}
