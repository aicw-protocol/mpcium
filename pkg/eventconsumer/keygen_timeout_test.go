package eventconsumer

import (
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestKeyGenTimeout_DefaultAndOverride(t *testing.T) {
	t.Cleanup(func() { viper.Set(KeygenTimeoutConfigKey, 0) })

	viper.Set(KeygenTimeoutConfigKey, 0)
	if got := KeyGenTimeout(); got != DefaultKeyGenTimeOut {
		t.Fatalf("default KeyGenTimeout = %s, want %s", got, DefaultKeyGenTimeOut)
	}

	viper.Set(KeygenTimeoutConfigKey, 45)
	if got := KeyGenTimeout(); got != 45*time.Second {
		t.Fatalf("override KeyGenTimeout = %s, want 45s", got)
	}

	// The JetStream reply wait must always exceed the ceremony budget so the
	// event consumer reports success/error before the consumer NAKs.
	if keygenResponseTimeout() <= KeyGenTimeout() {
		t.Fatalf("keygenResponseTimeout (%s) must be > KeyGenTimeout (%s)",
			keygenResponseTimeout(), KeyGenTimeout())
	}
}
