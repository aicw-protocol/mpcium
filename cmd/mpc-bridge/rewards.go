package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

func nodeWebRewardBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("AICW_NODE_WEB_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(viper.GetString("aicw.node_web_url")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return ""
}

// postMpcRewardEvent credits TAICW to the MPC committee for walletId (fire-and-forget).
func postMpcRewardEvent(walletID, eventType, txSignature string) {
	base := nodeWebRewardBaseURL()
	if base == "" {
		return
	}
	walletID = strings.TrimSpace(walletID)
	eventType = strings.TrimSpace(eventType)
	if walletID == "" || eventType == "" {
		return
	}

	go func() {
		payload := map[string]string{
			"walletId":  walletID,
			"eventType": eventType,
		}
		if txSignature != "" {
			payload["txSignature"] = txSignature
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[rewards] marshal: %v", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			base+"/api/rewards/mpc-event",
			bytes.NewReader(raw),
		)
		if err != nil {
			log.Printf("[rewards] request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("[rewards] post mpc-event: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			log.Printf("[rewards] mpc-event HTTP %d (wallet=%s type=%s)", resp.StatusCode, walletID, eventType)
			return
		}
		log.Printf("[rewards] credited %s for wallet %s", eventType, walletID)
	}()
}
