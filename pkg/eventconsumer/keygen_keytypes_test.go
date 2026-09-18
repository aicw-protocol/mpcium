package eventconsumer

import (
	"testing"

	"github.com/spf13/viper"

	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/fystack/mpcium/pkg/types"
)

func TestKeygenKeyTypes_DefaultIsEdDSAOnly(t *testing.T) {
	t.Cleanup(func() { viper.Set(types.KeygenKeyTypesConfigKey, nil) })
	viper.Set(types.KeygenKeyTypesConfigKey, nil)

	kts, err := KeygenKeyTypes()
	if err != nil {
		t.Fatal(err)
	}
	sts := keygenSessionTypesFor(kts)
	if len(sts) != 1 || sts[0] != mpc.SessionTypeEDDSA {
		t.Fatalf("default session types = %v, want [session_eddsa]", sts)
	}
}

func TestKeygenKeyTypes_BothWhenConfigured(t *testing.T) {
	t.Cleanup(func() { viper.Set(types.KeygenKeyTypesConfigKey, nil) })
	viper.Set(types.KeygenKeyTypesConfigKey, []string{"ed25519", "secp256k1"})

	kts, err := KeygenKeyTypes()
	if err != nil {
		t.Fatal(err)
	}
	sts := keygenSessionTypesFor(kts)
	if len(sts) != 2 || sts[0] != mpc.SessionTypeEDDSA || sts[1] != mpc.SessionTypeECDSA {
		t.Fatalf("session types = %v, want [session_eddsa session_ecdsa]", sts)
	}
}

// The request's key_types win over the node default; an empty request falls
// back to the default; garbage is rejected (never silently defaulted, since
// every committee member must derive the same session set).
func TestResolveKeygenSessionTypes(t *testing.T) {
	ec := &eventConsumer{keygenSessionTypes: []mpc.SessionType{mpc.SessionTypeEDDSA}}

	got, err := ec.resolveKeygenSessionTypes(nil)
	if err != nil || len(got) != 1 || got[0] != mpc.SessionTypeEDDSA {
		t.Fatalf("empty request -> default, got %v err %v", got, err)
	}

	got, err = ec.resolveKeygenSessionTypes([]types.KeyType{types.KeyTypeEd25519, types.KeyTypeSecp256k1})
	if err != nil || len(got) != 2 || got[0] != mpc.SessionTypeEDDSA || got[1] != mpc.SessionTypeECDSA {
		t.Fatalf("request [ed25519 secp256k1] -> %v err %v", got, err)
	}

	got, err = ec.resolveKeygenSessionTypes([]types.KeyType{types.KeyTypeSecp256k1})
	if err != nil || len(got) != 1 || got[0] != mpc.SessionTypeECDSA {
		t.Fatalf("request [secp256k1] -> %v err %v", got, err)
	}

	if _, err := ec.resolveKeygenSessionTypes([]types.KeyType{"bls"}); err == nil {
		t.Fatal("unknown key type in request must be rejected")
	}
}

func TestKeygenKeyTypes_InvalidRejected(t *testing.T) {
	t.Cleanup(func() { viper.Set(types.KeygenKeyTypesConfigKey, nil) })
	viper.Set(types.KeygenKeyTypesConfigKey, []string{"bls"})

	if _, err := KeygenKeyTypes(); err == nil {
		t.Fatal("expected error for unknown key type")
	}
}
