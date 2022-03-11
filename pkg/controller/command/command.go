/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/types"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vct/pkg/controller/errors"
)

// Command methods.
const (
	GetSTH            = "getSTH"
	GetSTHConsistency = "getSTHConsistency"
	GetEntries        = "getEntries"
	GetProofByHash    = "getProofByHash"
	GetEntryAndProof  = "getEntryAndProof"
	GetIssuers        = "getIssuers"
	Webfinger         = "webfinger"
	AddVC             = "addVC"

	PublicKeyType = "https://trustbloc.dev/ns/public-key"
	LedgerType    = "https://trustbloc.dev/ns/ledger-type"
)

// KeyManager manages keys and their storage.
type KeyManager kms.KeyManager

// TrillianLogClient is the API client for TrillianLog service.
type TrillianLogClient trillian.TrillianLogClient

// Crypto provides all crypto operations.
type Crypto crypto.Crypto

// Key holds info about a key that is using for signing.
type Key struct {
	ID   string
	Type kms.KeyType
}

// Cmd is a controller for commands.
type Cmd struct {
	baseURL string
	logs    map[string]Log
	VCLogID [32]byte
	kh      interface{}
	vdr     vdr.Registry
	kms     KeyManager
	crypto  crypto.Crypto
	PubKey  []byte
	alg     *SignatureAndHashAlgorithm
	loaders map[string]jsonld.DocumentLoader
}

type permission int32

const (
	read  permission = 'r'
	write permission = 'w'
)

// Log represents the log.
type Log struct {
	// ID trillian`s log id.
	ID         int64
	Alias      string
	Permission string
	Endpoint   string
	Issuers    []string
	Client     TrillianLogClient
}

// Config for the Cmd.
type Config struct {
	KMS             KeyManager
	Crypto          crypto.Crypto
	VDR             vdr.Registry
	Logs            []Log
	DocumentLoaders map[string]jsonld.DocumentLoader // alias -> loader
	Key             Key
	BaseURL         string
}

// nolint: gochecknoglobals
var (
	once                        sync.Once
	addVCParseCredentialLatency monitoring.Histogram
)

// nolint: lll
func createMetrics(mf monitoring.MetricFactory) {
	addVCParseCredentialLatency = mf.NewHistogram("add_vc_parse_credential_latency", "Latency of parse credential (add-vc operation)", "alias")
}

// New returns commands controller.
func New(cfg *Config, mf monitoring.MetricFactory) (*Cmd, error) {
	if mf == nil {
		mf = monitoring.InertMetricFactory{}
	}

	once.Do(func() { createMetrics(mf) })

	alg, err := signatureAndHashAlgorithmByKeyType(cfg.Key.Type)
	if err != nil {
		return nil, fmt.Errorf("key type %v is not supported", cfg.Key.Type)
	}

	kh, err := cfg.KMS.Get(cfg.Key.ID)
	if err != nil {
		return nil, fmt.Errorf("kms get kh: %w", err)
	}

	pubBytes, _, err := cfg.KMS.ExportPubKeyBytes(cfg.Key.ID)
	if err != nil {
		return nil, fmt.Errorf("export pub key bytes: %w", err)
	}

	if len(pubBytes) == 0 {
		return nil, fmt.Errorf("public key is empty")
	}

	logs := make(map[string]Log)
	for _, log := range cfg.Logs {
		logs[log.Alias] = log
	}

	return &Cmd{
		vdr:     cfg.VDR,
		PubKey:  pubBytes,
		VCLogID: sha256.Sum256(pubBytes),
		logs:    logs,
		kms:     cfg.KMS,
		kh:      kh,
		crypto:  cfg.Crypto,
		alg:     alg,
		baseURL: cfg.BaseURL,
		loaders: cfg.DocumentLoaders,
	}, nil
}

// GetHandlers returns list of all commands supported by this controller.
func (c *Cmd) GetHandlers() []Handler {
	return []Handler{
		NewCmdHandler(GetSTHConsistency, c.GetSTHConsistency),
		NewCmdHandler(GetSTH, c.GetSTH),
		NewCmdHandler(GetEntries, c.GetEntries),
		NewCmdHandler(GetProofByHash, c.GetProofByHash),
		NewCmdHandler(GetEntryAndProof, c.GetEntryAndProof),
		NewCmdHandler(GetIssuers, c.GetIssuers),
		NewCmdHandler(Webfinger, c.Webfinger),
		NewCmdHandler(AddVC, c.AddVC),
	}
}

// GetIssuers returns issuers.
func (c *Cmd) GetIssuers(w io.Writer, r io.Reader) error {
	var alias string

	if err := json.NewDecoder(r).Decode(&alias); err != nil {
		return fmt.Errorf("%w: decode alias failed", errors.ErrInternal)
	}

	if err := c.hasPermissions(alias, read); err != nil {
		return fmt.Errorf("has permissions: %w", err)
	}

	return json.NewEncoder(w).Encode(c.logs[alias].Issuers) // nolint: wrapcheck
}

// Webfinger returns discovery info.
func (c *Cmd) Webfinger(w io.Writer, r io.Reader) error {
	var alias string

	if err := json.NewDecoder(r).Decode(&alias); err != nil {
		return fmt.Errorf("%w: decode alias failed", errors.ErrInternal)
	}

	sub := c.baseURL + "/" + alias
	// TODO: add alternate links
	return json.NewEncoder(w).Encode(&WebFingerResponse{
		Subject: sub,
		Properties: map[string]interface{}{
			PublicKeyType: c.PubKey,
			LedgerType:    "vct-v1",
		},
		Links: []WebFingerLink{
			{Rel: "self", Href: sub},
		},
	}) // nolint: wrapcheck
}

// CreateLeaf creates MerkleTreeLeaf.
func CreateLeaf(timestamp uint64, vc *verifiable.Credential) (*MerkleTreeLeaf, error) {
	proofs := vc.Proofs
	vc.Proofs = nil

	defer func() { vc.Proofs = proofs }()

	credentialWithoutProofs, err := json.Marshal(vc)
	if err != nil {
		return nil, fmt.Errorf("marshal credential: %w", err)
	}

	return &MerkleTreeLeaf{
		Version:  V1,
		LeafType: TimestampedEntryLeafType,
		TimestampedEntry: &TimestampedEntry{
			EntryType: VCLogEntryType,
			Timestamp: timestamp,
			VCEntry:   credentialWithoutProofs,
		},
	}, nil
}

func (c *Cmd) hasPermissions(alias string, perm permission) error {
	if _, ok := c.logs[alias]; !ok {
		return errors.NewNotFoundError(fmt.Errorf("alias %q is not supported", alias))
	}

	for _, _perm := range c.logs[alias].Permission {
		if perm == permission(_perm) {
			return nil
		}
	}

	return errors.NewBadRequestError(fmt.Errorf("action forbidden for %q", alias))
}

// AddVC adds verifiable credential to log.
func (c *Cmd) AddVC(w io.Writer, r io.Reader) error { // nolint: funlen
	var req AddVCRequest

	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return fmt.Errorf("decode AddVC request: %w", errors.ErrInternal)
	}

	if err := c.hasPermissions(req.Alias, write); err != nil {
		return fmt.Errorf("has permissions: %w", err)
	}

	loader, ok := c.loaders[req.Alias]
	if !ok {
		return fmt.Errorf("no document loader found for alias %s", req.Alias)
	}

	parseCredentialTime := time.Now()

	vc, err := verifiable.ParseCredential(req.VCEntry, verifiable.WithPublicKeyFetcher(
		verifiable.NewVDRKeyResolver(c.vdr).PublicKeyFetcher(),
	), verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return errors.NewBadRequestError(fmt.Errorf("parse credential: %w", err))
	}

	addVCParseCredentialLatency.Observe(time.Since(parseCredentialTime).Seconds(), req.Alias)

	if len(c.logs[req.Alias].Issuers) > 0 && !contains(c.logs[req.Alias].Issuers, vc.Issuer.ID) {
		return fmt.Errorf("%w: issuer %s is not in a list", errors.ErrBadRequest, vc.Issuer.ID)
	}

	leaf, err := CreateLeaf(uint64(time.Now().UnixNano()/int64(time.Millisecond)), vc)
	if err != nil {
		return fmt.Errorf("create leaf: %w", err)
	}

	leafData, err := json.Marshal(leaf)
	if err != nil {
		return errors.NewStatusInternalServerError(fmt.Errorf("marshal MerkleTreeLeaf: %w", err))
	}

	extraData, err := json.Marshal(vc.Proofs)
	if err != nil {
		return errors.NewStatusInternalServerError(fmt.Errorf("marshal credential proofs: %w", err))
	}

	leafIDHash := sha256.Sum256(leaf.TimestampedEntry.VCEntry)

	resp, err := c.logs[req.Alias].Client.QueueLeaf(context.Background(), &trillian.QueueLeafRequest{
		LogId: c.logs[req.Alias].ID,
		Leaf: &trillian.LogLeaf{
			LeafValue:        leafData,
			ExtraData:        extraData,
			LeafIdentityHash: leafIDHash[:],
		},
	})
	if err != nil {
		return fmt.Errorf("queue leaf: %w", err)
	}

	if resp.QueuedLeaf == nil {
		return fmt.Errorf("%w: no leaf", errors.ErrInternal)
	}

	var loggedLeaf MerkleTreeLeaf
	if err = json.Unmarshal(resp.QueuedLeaf.Leaf.LeafValue, &loggedLeaf); err != nil {
		return errors.NewStatusInternalServerError(fmt.Errorf("failed to reconstruct MerkleTreeLeaf: %w", err))
	}

	sct, err := c.signV1VCTS(&loggedLeaf)
	if err != nil {
		return fmt.Errorf("sign V1 VCTS: %w", err)
	}

	signature, err := json.Marshal(sct)
	if err != nil {
		return fmt.Errorf("marshal DigitallySigned payload: %w", err)
	}

	return json.NewEncoder(w).Encode(AddVCResponse{ // nolint: wrapcheck
		SVCTVersion: V1,
		Timestamp:   loggedLeaf.TimestampedEntry.Timestamp,
		ID:          c.VCLogID[:],
		Extensions:  base64.StdEncoding.EncodeToString(loggedLeaf.TimestampedEntry.Extensions),
		Signature:   signature,
	})
}

// GetSTH retrieves the latest signed tree head.
func (c *Cmd) GetSTH(w io.Writer, r io.Reader) error {
	var alias string

	if err := json.NewDecoder(r).Decode(&alias); err != nil {
		return fmt.Errorf("%w: decode alias failed", errors.ErrInternal)
	}

	if err := c.hasPermissions(alias, read); err != nil {
		return fmt.Errorf("has permissions: %w", err)
	}

	req := trillian.GetLatestSignedLogRootRequest{LogId: c.logs[alias].ID}

	resp, err := c.logs[alias].Client.GetLatestSignedLogRoot(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("get latest signed log root: %w", err)
	}

	if resp.GetSignedLogRoot() == nil {
		return fmt.Errorf("%w: no signed log root returned", errors.ErrInternal)
	}

	var root types.LogRootV1
	if err = root.UnmarshalBinary(resp.SignedLogRoot.GetLogRoot()); err != nil {
		return fmt.Errorf("unmarshal binary: %w", err)
	}

	ths, err := c.signV1TreeHead(root)
	if err != nil {
		return fmt.Errorf("sign tree head (v1): %w", err)
	}

	treeHeadSignature, err := json.Marshal(ths)
	if err != nil {
		return fmt.Errorf("marshal DigitallySigned payload: %w", err)
	}

	return json.NewEncoder(w).Encode(GetSTHResponse{ // nolint: wrapcheck
		TreeSize:          root.TreeSize,
		SHA256RootHash:    root.RootHash,
		Timestamp:         root.TimestampNanos / uint64(time.Millisecond),
		TreeHeadSignature: treeHeadSignature,
	})
}

// GetEntries retrieves entries from log.
func (c *Cmd) GetEntries(w io.Writer, r io.Reader) error { // nolint: funlen
	const maxRange = 1000

	var request *GetEntriesRequest

	if err := json.NewDecoder(r).Decode(&request); err != nil {
		return fmt.Errorf("decode GetEntries request: %w", err)
	}

	if err := request.Validate(); err != nil {
		return fmt.Errorf("validate GetEntries request: %w", err)
	}

	if err := c.hasPermissions(request.Alias, read); err != nil {
		return fmt.Errorf("has permissions: %w", err)
	}

	if request.End-request.Start+1 > maxRange {
		request.End = request.Start + maxRange - 1
	}

	req := trillian.GetLeavesByRangeRequest{
		LogId:      c.logs[request.Alias].ID,
		StartIndex: request.Start,
		Count:      request.End + 1 - request.Start,
	}

	resp, err := c.logs[request.Alias].Client.GetLeavesByRange(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("get leaves by range: %w", err)
	}

	var currentRoot types.LogRootV1
	if err := currentRoot.UnmarshalBinary(resp.GetSignedLogRoot().GetLogRoot()); err != nil {
		return fmt.Errorf("%w: unmarshal binary: %v", errors.ErrInternal, resp.GetSignedLogRoot().GetLogRoot())
	}

	if currentRoot.TreeSize <= uint64(request.Start) {
		return fmt.Errorf("%w: need tree size: %d to get leaves but only got: %d",
			errors.ErrInternal, request.Start+1, currentRoot.TreeSize,
		)
	}

	if len(resp.Leaves) > int(req.Count) {
		return fmt.Errorf("%w: too many leaves: got %d in range [%d,%d]",
			errors.ErrInternal, len(resp.Leaves), request.Start, request.End,
		)
	}

	for i, leaf := range resp.Leaves {
		if leaf.LeafIndex != request.Start+int64(i) {
			return fmt.Errorf("%w: unexpected leaf index: rsp.Leaves[%d].LeafIndex=%d for range [%d,%d]",
				errors.ErrInternal, i, leaf.LeafIndex, request.Start, request.End,
			)
		}
	}

	entries := make([]LeafEntry, len(resp.Leaves))

	for i, leaf := range resp.Leaves {
		entries[i] = LeafEntry{
			LeafInput: leaf.LeafValue,
			ExtraData: leaf.ExtraData,
		}
	}

	return json.NewEncoder(w).Encode(GetEntriesResponse{Entries: entries}) // nolint: wrapcheck
}

// GetEntryAndProof retrieves entry and merkle audit proof from log.
func (c *Cmd) GetEntryAndProof(w io.Writer, r io.Reader) error {
	var request *GetEntryAndProofRequest

	if err := json.NewDecoder(r).Decode(&request); err != nil {
		return fmt.Errorf("decode GetEntryAndProof request: %w", err)
	}

	if err := request.Validate(); err != nil {
		return fmt.Errorf("validate GetEntryAndProof request: %w", err)
	}

	if err := c.hasPermissions(request.Alias, read); err != nil {
		return fmt.Errorf("has permissions: %w", err)
	}

	req := trillian.GetEntryAndProofRequest{
		LogId:     c.logs[request.Alias].ID,
		LeafIndex: request.LeafIndex,
		TreeSize:  request.TreeSize,
	}

	resp, err := c.logs[request.Alias].Client.GetEntryAndProof(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("get entry and proof: %w", err)
	}

	var currentRoot types.LogRootV1
	if err := currentRoot.UnmarshalBinary(resp.GetSignedLogRoot().GetLogRoot()); err != nil {
		return fmt.Errorf("%w: unmarshal binary: %v", errors.ErrInternal, resp.GetSignedLogRoot().GetLogRoot())
	}

	if currentRoot.TreeSize < uint64(request.TreeSize) {
		return fmt.Errorf("%w: need tree size: %d for proof, got: %d",
			errors.ErrBadRequest, req.TreeSize, currentRoot.TreeSize,
		)
	}

	if resp.Leaf == nil || len(resp.Leaf.LeafValue) == 0 || resp.Proof == nil {
		return fmt.Errorf("%w: corrupted data received: %v", errors.ErrInternal, resp)
	}

	if request.TreeSize > 1 && len(resp.Proof.Hashes) == 0 {
		return fmt.Errorf("%w: no proof: %v", errors.ErrInternal, resp)
	}

	return json.NewEncoder(w).Encode(GetEntryAndProofResponse{ // nolint: wrapcheck
		LeafInput: resp.Leaf.LeafValue,
		ExtraData: resp.Leaf.ExtraData,
		AuditPath: resp.Proof.Hashes,
	})
}

// GetProofByHash retrieves Merkle Audit proof from Log by leaf hash.
func (c *Cmd) GetProofByHash(w io.Writer, r io.Reader) error {
	var request *GetProofByHashRequest

	if err := json.NewDecoder(r).Decode(&request); err != nil {
		return fmt.Errorf("decode GetProofByHash request: %w", err)
	}

	if err := request.Validate(); err != nil {
		return fmt.Errorf("validate GetProofByHash request: %w", err)
	}

	if err := c.hasPermissions(request.Alias, read); err != nil {
		return fmt.Errorf("has permissions: %w", err)
	}

	leafHash, err := base64.StdEncoding.DecodeString(request.Hash)
	if err != nil {
		return errors.NewBadRequestError(fmt.Errorf("invalid base64 hash: %w", err))
	}

	req := trillian.GetInclusionProofByHashRequest{
		LogId:           c.logs[request.Alias].ID,
		LeafHash:        leafHash,
		TreeSize:        request.TreeSize,
		OrderBySequence: true,
	}

	resp, err := c.logs[request.Alias].Client.GetInclusionProofByHash(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("get leaves by range: %w", err)
	}

	var currentRoot types.LogRootV1
	if err := currentRoot.UnmarshalBinary(resp.GetSignedLogRoot().GetLogRoot()); err != nil {
		return fmt.Errorf("%w: unmarshal binary: %v", errors.ErrInternal, resp.GetSignedLogRoot().GetLogRoot())
	}

	if currentRoot.TreeSize < uint64(request.TreeSize) {
		return fmt.Errorf("%w: got tree size: %d but we expected: %d",
			errors.ErrNotFound, currentRoot.TreeSize, request.TreeSize,
		)
	}

	if len(resp.Proof) == 0 {
		return fmt.Errorf("%w: no proof", errors.ErrNotFound)
	}

	return json.NewEncoder(w).Encode(GetProofByHashResponse{ // nolint: wrapcheck
		LeafIndex: resp.Proof[0].LeafIndex,
		AuditPath: resp.Proof[0].Hashes,
	})
}

// GetSTHConsistency retrieves merkle consistency proofs between signed tree heads.
func (c *Cmd) GetSTHConsistency(w io.Writer, r io.Reader) error {
	var request *GetSTHConsistencyRequest

	if err := json.NewDecoder(r).Decode(&request); err != nil {
		return fmt.Errorf("decode GetSTHConsistency request: %w", err)
	}

	if err := request.Validate(); err != nil {
		return fmt.Errorf("validate GetSTHConsistency request: %w", err)
	}

	if err := c.hasPermissions(request.Alias, read); err != nil {
		return fmt.Errorf("has permissions: %w", err)
	}

	// TODO: if FirstTreeSize is zero rpc returns bad request (rpc error: code = InvalidArgument
	//  desc = GetConsistencyProofRequest.FirstTreeSize: 0, want > 0)
	//  Need to figure out what to return error or empty response (certificate-transparency-go uses empty response).
	if request.FirstTreeSize == 0 {
		return json.NewEncoder(w).Encode(GetSTHConsistencyResponse{}) // nolint: wrapcheck
	}

	req := trillian.GetConsistencyProofRequest{
		LogId:          c.logs[request.Alias].ID,
		FirstTreeSize:  request.FirstTreeSize,
		SecondTreeSize: request.SecondTreeSize,
	}

	resp, err := c.logs[request.Alias].Client.GetConsistencyProof(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("get consistency proof: %w", err)
	}

	var root types.LogRootV1
	if err := root.UnmarshalBinary(resp.GetSignedLogRoot().GetLogRoot()); err != nil {
		return fmt.Errorf("%w: unmarshal binary: %v", errors.ErrInternal, resp.GetSignedLogRoot().GetLogRoot())
	}

	if root.TreeSize < uint64(request.SecondTreeSize) {
		return fmt.Errorf("%w: need tree size: %d for proof but only got: %d",
			errors.ErrValidation, request.SecondTreeSize, root.TreeSize,
		)
	}

	return json.NewEncoder(w).Encode(GetSTHConsistencyResponse{ // nolint: wrapcheck
		Consistency: resp.Proof.GetHashes(),
	})
}

// CreateVCTimestampSignature creates VCTimestampSignature structure.
func CreateVCTimestampSignature(leaf *MerkleTreeLeaf) *VCTimestampSignature {
	return &VCTimestampSignature{
		SVCTVersion:   V1,
		SignatureType: VCTimestampSignatureType,
		Timestamp:     leaf.TimestampedEntry.Timestamp,
		EntryType:     leaf.TimestampedEntry.EntryType,
		VCEntry:       leaf.TimestampedEntry.VCEntry,
		Extensions:    leaf.TimestampedEntry.Extensions,
	}
}

func (c *Cmd) signV1VCTS(leaf *MerkleTreeLeaf) (DigitallySigned, error) {
	data, err := json.Marshal(CreateVCTimestampSignature(leaf))
	if err != nil {
		return DigitallySigned{}, fmt.Errorf("marshal VCTimestampSignature: %w", err)
	}

	signature, err := c.crypto.Sign(data, c.kh)
	if err != nil {
		return DigitallySigned{}, fmt.Errorf("sign TreeHeadSignature: %w", err)
	}

	return DigitallySigned{
		Algorithm: *c.alg,
		Signature: signature,
	}, nil
}

func (c *Cmd) signV1TreeHead(root types.LogRootV1) (DigitallySigned, error) {
	sthBytes, err := json.Marshal(TreeHeadSignature{
		Version:        V1,
		SignatureType:  TreeHeadSignatureType,
		Timestamp:      root.TimestampNanos / uint64(time.Millisecond),
		TreeSize:       root.TreeSize,
		SHA256RootHash: root.RootHash,
	})
	if err != nil {
		return DigitallySigned{}, fmt.Errorf("marshal TreeHeadSignature: %w", err)
	}

	signature, err := c.crypto.Sign(sthBytes, c.kh)
	if err != nil {
		return DigitallySigned{}, fmt.Errorf("sign TreeHeadSignature: %w", err)
	}

	return DigitallySigned{
		Algorithm: *c.alg,
		Signature: signature,
	}, nil
}

// TODO: Need to support more keys.
func signatureAndHashAlgorithmByKeyType(keyType kms.KeyType) (*SignatureAndHashAlgorithm, error) {
	switch keyType { // nolint: exhaustive
	case kms.ECDSAP256TypeDER:
		return &SignatureAndHashAlgorithm{
			Hash:      SHA256Hash,
			Signature: ECDSASignature,
			Type:      kms.ECDSAP256TypeDER,
		}, nil
	case kms.ECDSAP256TypeIEEEP1363:
		return &SignatureAndHashAlgorithm{
			Hash:      SHA256Hash,
			Signature: ECDSASignature,
			Type:      kms.ECDSAP256TypeIEEEP1363,
		}, nil
	default:
		return nil, fmt.Errorf("%w: key type %v is not supported", errors.ErrInternal, keyType)
	}
}

func contains(s []string, e string) bool {
	for i := range s {
		if s[i] == e {
			return true
		}
	}

	return false
}
