/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/vct/pkg/controller/errors"
)

// Version type definition.
type Version uint8

// Version constants.
const (
	V1 Version = 0
)

// SignatureAlgorithm type definition.
type SignatureAlgorithm string

// SignatureAlgorithm constants.
const (
	ECDSASignature SignatureAlgorithm = "ECDSA"
	EDDSASignature SignatureAlgorithm = "EDDSA"
)

// SignatureType differentiates signatures.
type SignatureType uint64

// SignatureType constants.
const (
	VCTimestampSignatureType SignatureType = 100
	TreeHeadSignatureType    SignatureType = 101
)

// MerkleLeafType type definition.
type MerkleLeafType uint64

// MerkleLeafType constants.
const (
	TimestampedEntryLeafType MerkleLeafType = 100
)

// LogEntryType type definition.
type LogEntryType uint64

// LogEntryType constants.
const (
	VCLogEntryType LogEntryType = 100
)

// GetEntryAndProofRequest represents the request to get-entry-and-proof.
type GetEntryAndProofRequest struct {
	Alias     string `json:"alias"`
	LeafIndex int64  `json:"leaf_index"`
	TreeSize  int64  `json:"tree_size"`
}

// Validate validates data.
func (r *GetEntryAndProofRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: validate on nil value", errors.ErrValidation)
	}

	if r.TreeSize < 1 {
		return fmt.Errorf("%w: tree_size value must be greater than zero", errors.ErrValidation)
	}

	if r.LeafIndex < 0 {
		return fmt.Errorf("%w: leaf_index must be greater than or equal to zero", errors.ErrValidation)
	}

	if r.LeafIndex >= r.TreeSize {
		return fmt.Errorf("%w: leaf_index must be less than tree_size", errors.ErrValidation)
	}

	return nil
}

// GetEntryAndProofResponse represents the response to get-entry-and-proof.
type GetEntryAndProofResponse struct {
	LeafInput []byte   `json:"leaf_input"`
	ExtraData []byte   `json:"extra_data"`
	AuditPath [][]byte `json:"audit_path"`
}

// GetProofByHashRequest represents the request to the get-proof-by-hash.
type GetProofByHashRequest struct {
	Alias    string `json:"alias"`
	Hash     string `json:"hash"`
	TreeSize int64  `json:"tree_size"`
}

// Validate validates data.
func (r *GetProofByHashRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: validate on nil value", errors.ErrValidation)
	}

	if r.TreeSize < 1 {
		return fmt.Errorf("%w: tree_size value must be greater than zero", errors.ErrValidation)
	}

	return nil
}

// GetProofByHashResponse represents the response to the get-proof-by-hash.
type GetProofByHashResponse struct {
	LeafIndex int64    `json:"leaf_index"`
	AuditPath [][]byte `json:"audit_path"`
}

// GetEntriesRequest represents the request to the get-entries.
type GetEntriesRequest struct {
	Alias string `json:"alias"`
	Start int64  `json:"start"`
	End   int64  `json:"end"`
}

// GetEntriesResponse represents the response to the get-entries.
type GetEntriesResponse struct {
	Entries []LeafEntry `json:"entries"`
}

// LeafEntry represents a leaf in the Log's Merkle tree.
type LeafEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

// Validate validates data.
func (r *GetEntriesRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: validate on nil value", errors.ErrValidation)
	}

	if r.Start < 0 || r.End < 0 {
		return fmt.Errorf("%w: start %d and end %d values must be >= 0", errors.ErrValidation, r.Start, r.End)
	}

	if r.Start > r.End {
		return fmt.Errorf("%w: start %d and end %d values is not a valid range", errors.ErrValidation, r.Start, r.End)
	}

	return nil
}

// GetSTHConsistencyRequest represents the request to the get-sth-consistency.
type GetSTHConsistencyRequest struct {
	Alias          string `json:"alias"`
	FirstTreeSize  int64  `json:"first_tree_size"`
	SecondTreeSize int64  `json:"second_tree_size"`
}

// Validate validates data.
func (r *GetSTHConsistencyRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: validate on nil value", errors.ErrValidation)
	}

	if r.FirstTreeSize < 0 || r.SecondTreeSize < 0 {
		return fmt.Errorf("%w: first_tree_size %d and second_tree_size %d values must be >= 0",
			errors.ErrValidation, r.FirstTreeSize, r.SecondTreeSize,
		)
	}

	if r.FirstTreeSize > r.SecondTreeSize {
		return fmt.Errorf("%w: first_tree_size %d and second_tree_size %d values is not a valid range",
			errors.ErrValidation, r.FirstTreeSize, r.SecondTreeSize,
		)
	}

	return nil
}

// GetSTHConsistencyResponse represents the response to the get-sth-consistency.
type GetSTHConsistencyResponse struct {
	Consistency [][]byte `json:"consistency"`
}

// GetSTHResponse represents the response to the get-sth.
type GetSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`
	Timestamp         uint64 `json:"timestamp"`
	SHA256RootHash    []byte `json:"sha256_root_hash"`
	TreeHeadSignature []byte `json:"tree_head_signature"`
}

// TreeHeadSignature keeps the data over which the signature in an STH is created.
type TreeHeadSignature struct {
	Version        Version       `json:"version"`
	SignatureType  SignatureType `json:"signature_type"`
	Timestamp      uint64        `json:"timestamp"`
	TreeSize       uint64        `json:"tree_size"`
	SHA256RootHash []byte        `json:"sha_256_root_hash"`
}

// SignatureAndHashAlgorithm provides information about the algorithm used for the signature.
type SignatureAndHashAlgorithm struct {
	Signature SignatureAlgorithm `json:"signature"`
	Type      kms.KeyType        `json:"type"`
}

// DigitallySigned provides information about a signature.
type DigitallySigned struct {
	Algorithm SignatureAndHashAlgorithm `json:"algorithm"`
	Signature []byte                    `json:"signature"`
}

// MerkleTreeLeaf represents the deserialized structure of the hash input for the
// leaves of a log's Merkle tree.
type MerkleTreeLeaf struct {
	Version          Version           `json:"version"`
	LeafType         MerkleLeafType    `json:"leaf_type"`
	TimestampedEntry *TimestampedEntry `json:"timestamped_entry"`
}

// TimestampedEntry is part of the MerkleTreeLeaf structure.
type TimestampedEntry struct {
	Timestamp  uint64       `json:"timestamp"`
	EntryType  LogEntryType `json:"entry_type"`
	VCEntry    []byte       `json:"vc_entry"`
	Extensions []byte       `json:"extensions"`
}

// VCTimestampSignature keeps the data over which the signature is created.
type VCTimestampSignature struct {
	SVCTVersion   Version       `json:"svct_version"`
	SignatureType SignatureType `json:"signature_type"`
	Timestamp     uint64        `json:"timestamp"`
	EntryType     LogEntryType  `json:"entry_type"`
	VCEntry       []byte        `json:"vc_entry"`
	Extensions    []byte        `json:"extensions"`
}

// AddVCResponse represents the response to add-vc.
type AddVCResponse struct {
	SVCTVersion Version `json:"svct_version"`
	ID          []byte  `json:"id"`
	Timestamp   uint64  `json:"timestamp"`
	Extensions  string  `json:"extensions"`
	Signature   []byte  `json:"signature"`
}

// AddVCRequest represents the request to add-vc.
type AddVCRequest struct {
	Alias   string `json:"alias"`
	VCEntry []byte `json:"vc_entry"`
}

// WebFingerResponse web finger response.
type WebFingerResponse struct {
	Subject    string                 `json:"subject,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Links      []WebFingerLink        `json:"links,omitempty"`
}

// WebFingerLink web finger link.
type WebFingerLink struct {
	Rel  string `json:"rel,omitempty"`
	Type string `json:"type,omitempty"`
	Href string `json:"href,omitempty"`
}
