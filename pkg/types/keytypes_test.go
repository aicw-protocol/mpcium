package types

import "testing"

func TestParseKeyTypes(t *testing.T) {
	// Unset => AICW default: Ed25519 only (ECDSA keygen is opt-in).
	got, err := ParseKeyTypes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != KeyTypeEd25519 {
		t.Fatalf("ParseKeyTypes(nil) = %v, want [ed25519]", got)
	}

	// Explicit both, mixed case / whitespace / duplicates, order preserved.
	got, err = ParseKeyTypes([]string{" Ed25519 ", "SECP256K1", "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != KeyTypeEd25519 || got[1] != KeyTypeSecp256k1 {
		t.Fatalf("ParseKeyTypes(both) = %v, want [ed25519 secp256k1]", got)
	}

	// ECDSA only is allowed too.
	got, err = ParseKeyTypes([]string{"secp256k1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != KeyTypeSecp256k1 {
		t.Fatalf("ParseKeyTypes(secp) = %v, want [secp256k1]", got)
	}

	// Typos must fail loudly: a node silently falling back would desync the
	// cluster's session set and stall the peer barrier.
	if _, err := ParseKeyTypes([]string{"ed25519", "ecdsa"}); err == nil {
		t.Fatal("expected error for unknown key type")
	}
}
