package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/hashicorp/consul/api"
)

const keyinfoPrefix = "threshold_keyinfo/"

func main() {
	dbPath := flag.String("db", "", "BadgerDB path for this node (node must be stopped)")
	badgerPassword := flag.String("badger-password", "", "Badger encryption key (same as node BadgerPassword)")
	consulAddr := flag.String("consul", "", "Consul address (e.g. 127.0.0.1:8500)")
	apply := flag.Bool("apply", false, "Delete stale keys (default: dry-run)")
	flag.Parse()

	if *dbPath == "" || *badgerPassword == "" || *consulAddr == "" {
		flag.Usage()
		os.Exit(2)
	}

	logger.Init("production", false)

	consulClient, err := newConsulClient(*consulAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "consul client: %v\n", err)
		os.Exit(1)
	}
	kv := consulClient.KV()

	password := []byte(*badgerPassword)
	store, err := kvstore.NewBadgerKVStore(kvstore.BadgerConfig{
		NodeID:              "cleanup-old-shares",
		EncryptionKey:       password,
		BackupEncryptionKey: password,
		BackupDir:           os.TempDir(),
		DBPath:              *dbPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open badger db: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	keys, _, err := kv.Keys(keyinfoPrefix, "", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list consul keyinfo: %v\n", err)
		os.Exit(1)
	}

	var walletsScanned, staleFound, deleted int

	for _, consulKey := range keys {
		keyType, walletID, ok := parseKeyInfoConsulKey(consulKey)
		if !ok {
			logger.Warn("Skipping unparsable keyinfo key", "key", consulKey)
			continue
		}

		pair, _, err := kv.Get(consulKey, nil)
		if err != nil || pair == nil {
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			logger.Warn("Skipping keyinfo with missing value", "key", consulKey, "error", errMsg)
			continue
		}

		info := &keyinfo.KeyInfo{}
		if err := json.Unmarshal(pair.Value, info); err != nil {
			logger.Warn("Skipping keyinfo with invalid JSON", "key", consulKey, "error", err.Error())
			continue
		}
		if info.Version < 1 {
			continue
		}

		walletsScanned++
		candidates := staleKeysFor(keyType, walletID, info.Version)
		for _, key := range candidates {
			data, err := store.Get(key)
			if err != nil || len(data) == 0 {
				continue
			}
			staleFound++
			if *apply {
				if err := store.Delete(key); err != nil {
					fmt.Fprintf(os.Stderr, "delete %s: %v\n", key, err)
					os.Exit(1)
				}
				deleted++
				fmt.Printf("deleted %s\n", key)
			} else {
				fmt.Printf("[dry-run] would delete %s\n", key)
			}
		}
	}

	fmt.Printf("summary: wallets_scanned=%d stale_keys_found=%d deleted=%d apply=%v\n",
		walletsScanned, staleFound, deleted, *apply)
}

func staleKeysFor(keyType, walletID string, version int) []string {
	if version < 1 {
		return nil
	}
	base := fmt.Sprintf("%s:%s", keyType, walletID)
	keys := []string{base}
	for k := 1; k < version; k++ {
		keys = append(keys, fmt.Sprintf("%s_v%d", base, k))
	}
	return keys
}

func parseKeyInfoConsulKey(consulKey string) (keyType, walletID string, ok bool) {
	if !strings.HasPrefix(consulKey, keyinfoPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(consulKey, keyinfoPrefix)
	colon := strings.Index(rest, ":")
	if colon <= 0 || colon >= len(rest)-1 {
		return "", "", false
	}
	keyType = rest[:colon]
	if keyType != "ecdsa" && keyType != "eddsa" {
		return "", "", false
	}
	return keyType, rest[colon+1:], true
}

func newConsulClient(addr string) (*api.Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = addr
	return api.NewClient(cfg)
}
