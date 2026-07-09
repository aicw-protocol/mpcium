package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/dgraph-io/badger/v4"
)

const issuerRegionPrefix = "issuer_region:"

var isoCountryRe = regexp.MustCompile(`^[A-Z]{2}$`)

func issuerRegionKey(aicwPda string) []byte {
	return []byte(issuerRegionPrefix + aicwPda)
}

func normalizeIssuerRegionCode(code string) (string, error) {
	c := strings.ToUpper(strings.TrimSpace(code))
	if !isoCountryRe.MatchString(c) {
		return "", errors.New("countryCode must be ISO 3166-1 alpha-2 (e.g. KR)")
	}
	return c, nil
}

func putIssuerRegion(aicwPda, countryCode string) error {
	if bridgeState.secretDB == nil {
		return errors.New("secret db is not initialized")
	}
	pda := strings.TrimSpace(aicwPda)
	if pda == "" {
		return errors.New("aicwPda required")
	}
	code, err := normalizeIssuerRegionCode(countryCode)
	if err != nil {
		return err
	}
	return bridgeState.secretDB.Update(func(txn *badger.Txn) error {
		return txn.Set(issuerRegionKey(pda), []byte(code))
	})
}

func listIssuerRegions() (map[string]string, error) {
	if bridgeState.secretDB == nil {
		return nil, errors.New("secret db is not initialized")
	}
	out := make(map[string]string)
	err := bridgeState.secretDB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(issuerRegionPrefix)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := string(item.Key())
			pda := strings.TrimPrefix(key, issuerRegionPrefix)
			if pda == "" {
				continue
			}
			if err := item.Value(func(v []byte) error {
				out[pda] = string(v)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

type registerIssuerRegionRequest struct {
	AicwPda      string `json:"aicwPda"`
	CountryCode  string `json:"countryCode"`
	Country      string `json:"country"` // alias
}

func handleRegisterIssuerRegion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body registerIssuerRegionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := body.CountryCode
	if code == "" {
		code = body.Country
	}
	if err := putIssuerRegion(body.AicwPda, code); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	normalized, _ := normalizeIssuerRegionCode(code)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":      true,
		"aicwPda":      strings.TrimSpace(body.AicwPda),
		"countryCode":  normalized,
	})
}

func handleListIssuerRegions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	regions, err := listIssuerRegions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if regions == nil {
		regions = map[string]string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"regions": regions,
	})
}
