package mpc

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

const (
	PurposeKeygen  string = "keygen"
	PurposeSign    string = "sign"
	PurposeReshare string = "reshare"

	BackwardCompatibleVersion int = 0
	DefaultVersion            int = 1
)

type ID string

// AICW-FORK (production-gaps-review.md G-5): reject signing while an
// orchestrator-driven reshare is in flight for the wallet. Nil checker
// (upstream / orchestrator-less deployments) disables the guard.
type ReshareInflightChecker func(walletID string) (bool, error)

var ErrReshareInProgress = errors.New("reshare in progress for this wallet; retry after it completes")

type Node struct {
	nodeID  string
	peerIDs []string

	pubSub         messaging.PubSub
	direct         messaging.DirectMessaging
	kvstore        kvstore.KVStore
	keyinfoStore   keyinfo.Store
	ecdsaPreParams []*keygen.LocalPreParams
	identityStore  identity.Store
	peerRegistry   PeerRegistry
	ckd            *CKD

	reshareInflightChecker ReshareInflightChecker
}

func NewNode(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	peerRegistry PeerRegistry,
	identityStore identity.Store,
	ckd *CKD,
) *Node {
	start := time.Now()
	elapsed := time.Since(start)
	logger.Info("Starting new node, preparams is generated successfully!", "elapsed", elapsed.Milliseconds())

	node := &Node{
		nodeID:        nodeID,
		peerIDs:       peerIDs,
		pubSub:        pubSub,
		direct:        direct,
		kvstore:       kvstore,
		keyinfoStore:  keyinfoStore,
		peerRegistry:  peerRegistry,
		identityStore: identityStore,
		ckd:           ckd,
	}
	node.ecdsaPreParams = node.generatePreParams()

	// Start watching peers - ECDH is now handled by the registry
	go peerRegistry.WatchPeersReady()
	return node
}

func (p *Node) ID() string {
	return p.nodeID
}

func (p *Node) SetReshareInflightChecker(fn ReshareInflightChecker) {
	p.reshareInflightChecker = fn
}

func (p *Node) reshareInflight(walletID string) bool {
	if p.reshareInflightChecker == nil {
		return false
	}
	inflight, err := p.reshareInflightChecker(walletID)
	if err != nil {
		// Fail-open: a Consul outage must not block all signing.
		logger.Warn("Reshare inflight check failed; allowing signing", "walletID", walletID, "error", err.Error())
		return false
	}
	return inflight
}

// KeygenParty returns the committee (peer IDs including self) that will run the
// keygen for walletID. Used by the event consumer to skip nodes that are not
// part of a wallet's committee. AICW-FORK (auto_reshare_design.md §13.5).
func (p *Node) KeygenParty(walletID string) []string {
	return p.peerRegistry.GetKeygenParty(walletID)
}

func (p *Node) CreateKeyGenSession(
	sessionType SessionType,
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (KeyGenSession, error) {
	// AICW-FORK (§13.3/§13.4): committee-local ECDH gate. In legacy mode
	// EnsureCeremonyReady falls back to the full-cluster ArePeersReady() check,
	// so behavior is unchanged unless committee filtering is enabled. In
	// committee mode it scopes/triggers ECDH for the wallet's committee and
	// blocks until that committee is ceremony-ready (Consul-ready + ECDH keys).
	party := p.peerRegistry.GetKeygenParty(walletID)
	if err := p.peerRegistry.EnsureCeremonyReady(party); err != nil {
		return nil, fmt.Errorf("keygen ceremony not ready: %w", err)
	}

	keyInfo, _ := p.getKeyInfo(sessionType, walletID)
	if keyInfo != nil {
		return nil, fmt.Errorf("Key already exists: %s", walletID)
	}

	switch sessionType {
	case SessionTypeECDSA:
		return p.createECDSAKeyGenSession(walletID, threshold, DefaultVersion, resultQueue)
	case SessionTypeEDDSA:
		return p.createEDDSAKeyGenSession(walletID, threshold, DefaultVersion, resultQueue)
	default:
		return nil, fmt.Errorf("Unknown session type: %s", sessionType)
	}
}

func (p *Node) createECDSAKeyGenSession(walletID string, threshold int, version int, resultQueue messaging.MessageQueue) (KeyGenSession, error) {
	// AICW-FORK (auto_reshare_design.md §13.5): the keygen party is the wallet's
	// committee (deterministic, tier-sized), not necessarily every ready peer.
	// The default registry returns all ready peers, so behavior is unchanged
	// unless AICW committee filtering is enabled.
	readyPeerIDs := p.peerRegistry.GetKeygenParty(walletID)
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, version)
	session := newECDSAKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.ecdsaPreParams[0],
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) createEDDSAKeyGenSession(walletID string, threshold int, version int, resultQueue messaging.MessageQueue) (KeyGenSession, error) {
	// AICW-FORK (§13.5): keygen party = wallet committee (see ECDSA variant).
	readyPeerIDs := p.peerRegistry.GetKeygenParty(walletID)
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, version)
	session := newEDDSAKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateSigningSession(
	sessionType SessionType,
	walletID string,
	txID string,
	networkInternalCode string,
	resultTopic string,
	resultQueue messaging.MessageQueue,
	derivationPath []uint32,
	idempotentKey string,
) (SigningSession, error) {
	if p.reshareInflight(walletID) {
		return nil, ErrReshareInProgress
	}

	version := p.getVersion(sessionType, walletID)
	keyInfo, err := p.getKeyInfo(sessionType, walletID)
	if err != nil {
		return nil, err
	}

	// AICW-FORK (§13.4): committee-local ECDH for signing. The signing committee
	// is keyInfo.ParticipantPeerIDs; ensure symmetric keys with those members are
	// (re)established — important after a node restart where the pairwise ECDH
	// state was lost. Best-effort (no-op in legacy mode); the session barrier
	// (WaitForPeersReady) provides the hard synchronization.
	if p.peerRegistry.CeremonyFilterEnabled() {
		if err := p.peerRegistry.EnsureCeremonyECDH(keyInfo.ParticipantPeerIDs); err != nil {
			logger.Warn("Signing: ensure committee ECDH failed (continuing)", "walletID", walletID, "error", err.Error())
		}
	}

	readyPeers := p.peerRegistry.GetReadyPeersIncludeSelf()
	readyParticipantIDs := p.getReadyPeersForSession(keyInfo, readyPeers)

	logger.Info("Creating signing session",
		"type", sessionType,
		"readyPeers", readyPeers,
		"participantPeerIDs", keyInfo.ParticipantPeerIDs,
		"ready count", len(readyParticipantIDs),
		"min ready", keyInfo.Threshold+1,
		"version", version,
	)

	if len(readyParticipantIDs) < keyInfo.Threshold+1 {
		return nil, fmt.Errorf("not enough peers to create signing session! expected %d, got %d", keyInfo.Threshold+1, len(readyParticipantIDs))
	}

	if err := p.ensureNodeIsParticipant(keyInfo); err != nil {
		return nil, err
	}

	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyParticipantIDs, version)

	switch sessionType {
	case SessionTypeECDSA:
		return newECDSASigningSession(
			walletID,
			txID,
			networkInternalCode,
			resultTopic,
			p.pubSub,
			p.direct,
			readyParticipantIDs,
			selfPartyID,
			allPartyIDs,
			keyInfo.Threshold,
			p.ecdsaPreParams[0],
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			derivationPath,
			idempotentKey,
			p.ckd,
		), nil

	case SessionTypeEDDSA:
		return newEDDSASigningSession(
			walletID,
			txID,
			networkInternalCode,
			resultTopic,
			p.pubSub,
			p.direct,
			readyParticipantIDs,
			selfPartyID,
			allPartyIDs,
			keyInfo.Threshold,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			derivationPath,
			idempotentKey,
			p.ckd,
		), nil
	}

	return nil, errors.New("unknown session type")
}

// unionStrings returns the de-duplicated union of two string slices, preserving
// first-seen order. AICW-FORK helper for the reshare committee ECDH set (§13.4).
func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func (p *Node) getKeyInfo(sessionType SessionType, walletID string) (*keyinfo.KeyInfo, error) {
	var keyID string
	switch sessionType {
	case SessionTypeECDSA:
		keyID = fmt.Sprintf("ecdsa:%s", walletID)
	case SessionTypeEDDSA:
		keyID = fmt.Sprintf("eddsa:%s", walletID)
	default:
		return nil, errors.New("unsupported session type")
	}
	return p.keyinfoStore.Get(keyID)
}

func (p *Node) getReadyPeersForSession(keyInfo *keyinfo.KeyInfo, readyPeers []string) []string {
	// Ensure all participants are ready
	readyParticipantIDs := make([]string, 0, len(keyInfo.ParticipantPeerIDs))
	for _, peerID := range keyInfo.ParticipantPeerIDs {
		if slices.Contains(readyPeers, peerID) {
			readyParticipantIDs = append(readyParticipantIDs, peerID)
		}
	}

	return readyParticipantIDs
}

func (p *Node) ensureNodeIsParticipant(keyInfo *keyinfo.KeyInfo) error {
	if !slices.Contains(keyInfo.ParticipantPeerIDs, p.nodeID) {
		return ErrNotInParticipantList
	}
	return nil
}

func (p *Node) CreateReshareSession(
	sessionType SessionType,
	walletID string,
	newThreshold int,
	newPeerIDs []string,
	isNewPeer bool,
	resultQueue messaging.MessageQueue,
) (ReshareSession, error) {
	// 1. Check peer readiness
	count := p.peerRegistry.GetReadyPeersCount()
	if count < int64(newThreshold)+1 {
		return nil, fmt.Errorf(
			"not enough peers to create reshare session! Expected at least %d, got %d",
			newThreshold+1,
			count,
		)
	}

	if len(newPeerIDs) < newThreshold+1 {
		return nil, fmt.Errorf("new peer list is smaller than required t+1")
	}

	// 2. Make sure all new peers are ready
	readyNewPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	for _, peerID := range newPeerIDs {
		if !slices.Contains(readyNewPeerIDs, peerID) {
			return nil, fmt.Errorf("new peer %s is not ready", peerID)
		}
	}

	// 3. Load old key info
	keyPrefix, err := sessionKeyPrefix(sessionType)
	if err != nil {
		return nil, fmt.Errorf("failed to get session key prefix: %w", err)
	}
	keyInfoKey := fmt.Sprintf("%s:%s", keyPrefix, walletID)
	oldKeyInfo, err := p.keyinfoStore.Get(keyInfoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get old key info: %w", err)
	}

	readyPeers := p.peerRegistry.GetReadyPeersIncludeSelf()
	readyOldParticipantIDs := p.getReadyPeersForSession(oldKeyInfo, readyPeers)

	isInOldCommittee := slices.Contains(oldKeyInfo.ParticipantPeerIDs, p.nodeID)
	isInNewCommittee := slices.Contains(newPeerIDs, p.nodeID)

	// 4. Skip if not relevant
	if isNewPeer && !isInNewCommittee {
		logger.Info("Skipping new session: node is not in new committee", "walletID", walletID, "nodeID", p.nodeID)
		return nil, nil
	}
	if !isNewPeer && !isInOldCommittee {
		logger.Info("Skipping old session: node is not in old committee", "walletID", walletID, "nodeID", p.nodeID)
		return nil, nil
	}

	// AICW-FORK (§13.4): committee-local ECDH for reshare. TSS resharing
	// exchanges messages across the old ∪ new committees, so scope/trigger ECDH
	// over that union to establish symmetric keys before the ceremony. This is
	// best-effort (no-op in legacy mode); the reshare barrier and orchestrator
	// retries provide the hard synchronization.
	if p.peerRegistry.CeremonyFilterEnabled() {
		ceremony := unionStrings(oldKeyInfo.ParticipantPeerIDs, newPeerIDs)
		if err := p.peerRegistry.EnsureCeremonyECDH(ceremony); err != nil {
			logger.Warn("Reshare: ensure committee ECDH failed (continuing)", "walletID", walletID, "error", err.Error())
		}
	}

	logger.Info("Creating resharing session",
		"type", sessionType,
		"readyPeers", readyPeers,
		"participantPeerIDs", oldKeyInfo.ParticipantPeerIDs,
		"ready count", len(readyOldParticipantIDs),
		"min ready", oldKeyInfo.Threshold+1,
		"version", oldKeyInfo.Version,
		"isNewPeer", isNewPeer,
	)

	if len(readyOldParticipantIDs) < oldKeyInfo.Threshold+1 {
		return nil, fmt.Errorf("not enough peers to create resharing session! expected %d, got %d", oldKeyInfo.Threshold+1, len(readyOldParticipantIDs))
	}

	if !isNewPeer {
		if err := p.ensureNodeIsParticipant(oldKeyInfo); err != nil {
			return nil, err
		}
	}

	// 5. Generate party IDs
	version := p.getVersion(sessionType, walletID)
	oldSelf, oldAllPartyIDs := p.generatePartyIDs(PurposeKeygen, readyOldParticipantIDs, version)
	newSelf, newAllPartyIDs := p.generatePartyIDs(PurposeReshare, newPeerIDs, version+1)

	// 6. Pick identity and call session constructor
	var selfPartyID *tss.PartyID
	var participantPeerIDs []string
	if isNewPeer {
		selfPartyID = newSelf
		participantPeerIDs = newPeerIDs
	} else {
		selfPartyID = oldSelf
		participantPeerIDs = readyOldParticipantIDs
	}

	switch sessionType {
	case SessionTypeECDSA:
		preParams := p.ecdsaPreParams[0]
		if isNewPeer {
			// Alternate pre-params for new nodes based on version: v1->1, v2->0, v3->1...
			preParams = p.ecdsaPreParams[version%2]
			participantPeerIDs = newPeerIDs
		}
		// Old committee: participantPeerIDs stays readyOldParticipantIDs (set above).

		return NewECDSAReshareSession(
			walletID,
			p.pubSub,
			p.direct,
			participantPeerIDs,
			selfPartyID,
			oldAllPartyIDs,
			newAllPartyIDs,
			oldKeyInfo.Threshold,
			newThreshold,
			preParams,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			newPeerIDs,
			isNewPeer,
			oldKeyInfo.Version,
		), nil

	case SessionTypeEDDSA:
		return NewEDDSAReshareSession(
			walletID,
			p.pubSub,
			p.direct,
			participantPeerIDs,
			selfPartyID,
			oldAllPartyIDs,
			newAllPartyIDs,
			oldKeyInfo.Threshold,
			newThreshold,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			newPeerIDs,
			isNewPeer,
			oldKeyInfo.Version,
		), nil

	default:
		return nil, fmt.Errorf("unsupported session type: %v", sessionType)
	}
}

func ComposeReadyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func (p *Node) Close() {
	err := p.peerRegistry.Resign()
	if err != nil {
		logger.Error("Resign failed", err)
	}
}

func (p *Node) generatePreParams() []*keygen.LocalPreParams {
	start := time.Now()
	// Try to load from kvstore
	preParams := make([]*keygen.LocalPreParams, 2)
	for i := 0; i < 2; i++ {
		key := fmt.Sprintf("pre_params_%d", i)
		val, err := p.kvstore.Get(key)
		if err == nil && val != nil {
			preParams[i] = &keygen.LocalPreParams{}
			err = json.Unmarshal(val, preParams[i])
			if err != nil {
				logger.Fatal("Unmarshal pre params failed", err)
			}
			continue
		}
		// Not found, generate and save
		params, err := keygen.GeneratePreParams(5 * time.Minute)
		if err != nil {
			logger.Fatal("Generate pre params failed", err)
		}
		bytes, err := json.Marshal(params)
		if err != nil {
			logger.Fatal("Marshal pre params failed", err)
		}
		err = p.kvstore.Put(key, bytes)
		if err != nil {
			logger.Fatal("Save pre params failed", err)
		}
		preParams[i] = params
	}
	logger.Info("Generate pre params successfully!", "elapsed", time.Since(start).Milliseconds())
	return preParams
}

func (p *Node) getVersion(sessionType SessionType, walletID string) int {
	var composeKey string
	switch sessionType {
	case SessionTypeECDSA:
		composeKey = fmt.Sprintf("ecdsa:%s", walletID)
	case SessionTypeEDDSA:
		composeKey = fmt.Sprintf("eddsa:%s", walletID)
	default:
		logger.Fatal("Unknown session type", errors.New("Unknown session type"))
	}
	keyinfo, err := p.keyinfoStore.Get(composeKey)
	if err != nil {
		logger.Error("Get keyinfo failed", err, "walletID", walletID)
		return DefaultVersion
	}
	return keyinfo.Version
}

func sessionKeyPrefix(sessionType SessionType) (string, error) {
	switch sessionType {
	case SessionTypeECDSA:
		return "ecdsa", nil
	case SessionTypeEDDSA:
		return "eddsa", nil
	default:
		return "", fmt.Errorf("unsupported session type: %v", sessionType)
	}
}
