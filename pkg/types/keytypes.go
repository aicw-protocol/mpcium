package types

import (
	"fmt"
	"strings"
)

// KeygenKeyTypesConfigKey is the config key listing key families, e.g.
//
//	keygen_key_types: [ed25519]
//	keygen_key_types: [ed25519, secp256k1]
//
// AICW-FORK: on the Bridge it selects the families every new wallet gets; the
// choice is signed into GenerateKeyMessage.KeyTypes so independently operated
// nodes follow it without any config change. On nodes it is only the fallback
// for requests without key_types. Default is Ed25519 only (AICW is Solana
// first; the ECDSA keygen — Paillier/DLN proofs over 2048-bit moduli per peer
// pair — dominated ceremony time and its key was unused).
const KeygenKeyTypesConfigKey = "keygen_key_types"

// DefaultKeygenKeyTypes is used when KeygenKeyTypesConfigKey is not set.
var DefaultKeygenKeyTypes = []KeyType{KeyTypeEd25519}

// KeyTypeStrings renders key types as plain strings (logs, canonical payloads).
func KeyTypeStrings(kts []KeyType) []string {
	out := make([]string, len(kts))
	for i, kt := range kts {
		out[i] = string(kt)
	}
	return out
}

// ParseKeyTypes validates and normalises a configured key-type list. Entries are
// case-insensitive, whitespace-trimmed and de-duplicated while preserving the
// first-seen order. An empty input yields DefaultKeygenKeyTypes.
func ParseKeyTypes(in []string) ([]KeyType, error) {
	if len(in) == 0 {
		return append([]KeyType(nil), DefaultKeygenKeyTypes...), nil
	}
	seen := make(map[KeyType]bool, len(in))
	out := make([]KeyType, 0, len(in))
	for _, raw := range in {
		kt := KeyType(strings.ToLower(strings.TrimSpace(raw)))
		switch kt {
		case KeyTypeEd25519, KeyTypeSecp256k1:
		default:
			return nil, fmt.Errorf("%s: unknown key type %q (want ed25519 or secp256k1)", KeygenKeyTypesConfigKey, raw)
		}
		if seen[kt] {
			continue
		}
		seen[kt] = true
		out = append(out, kt)
	}
	return out, nil
}
