/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"time"

	"github.com/trustbloc/vct/pkg/controller/command"
)

// Response error message
//
// swagger:response genericError
type genericError struct { // nolint:unused,deadcode
	// in: body
	Body ErrorResponse
}

// Request message
//
// swagger:parameters addVCRequest
type addVCRequest struct { // nolint: unused,deadcode
	// Alias
	//
	// in: path
	// required: true
	Alias string `json:"alias"`

	// Verifiable Credentials https://www.w3.org/TR/vc-data-model
	//
	// in: body
	Body struct {
		Context           []string `json:"@context"`
		CredentialSubject struct {
			ID string `json:"id"`
		} `json:"credentialSubject"`
		ID           string    `json:"id"`
		IssuanceDate time.Time `json:"issuanceDate"`
		Issuer       string    `json:"issuer"`
		Type         []string  `json:"type"`
	}
}

// Response message
//
// swagger:response addVCResponse
type addVCResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		SVCTVersion uint8  `json:"svct_version"`
		ID          string `json:"id"`
		Timestamp   uint64 `json:"timestamp"`
		Extensions  string `json:"extensions"`
		Signature   string `json:"signature"`
	}
}

// Request message
//
// swagger:parameters getSTHRequest
type getSTHRequest struct { // nolint: unused,deadcode
	// Alias
	//
	// in: path
	// required: true
	Alias string `json:"alias"`
}

// Response message
//
// swagger:response getSTHResponse
type getSTHResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		TreeSize          uint64 `json:"tree_size"`
		Timestamp         uint64 `json:"timestamp"`
		SHA256RootHash    string `json:"sha256_root_hash"`
		TreeHeadSignature string `json:"tree_head_signature"`
	}
}

// Request message
//
// swagger:parameters getIssuersRequest
type getIssuersRequest struct { // nolint: unused,deadcode
	// Alias
	//
	// in: path
	// required: true
	Alias string `json:"alias"`
}

// Response message
//
// swagger:response getIssuersResponse
type getIssuersResponse struct { // nolint: unused,deadcode
	// in: body
	Body []string
}

// Request message
//
// swagger:parameters healthCheckRequest
type healthCheckRequest struct{} // nolint: unused,deadcode

// Response message
//
// swagger:response healthCheckResponse
type healthCheckResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Status      string    `json:"status"`
		CurrentTime time.Time `json:"current_time"`
	}
}

// Request message
//
// swagger:parameters webfingerRequest
type webfingerRequest struct { // nolint: unused,deadcode
	// Alias
	//
	// in: path
	// required: true
	Alias string `json:"alias"`
}

// Response message
//
// swagger:response webfingerResponse
type webfingerResponse struct { // nolint: unused,deadcode
	// in: body
	Body command.WebFingerResponse
}

// Request message
//
// swagger:parameters getSTHConsistencyRequest
type getSTHConsistencyRequest struct { // nolint: unused,deadcode
	// Alias
	//
	// in: path
	// required: true
	Alias string `json:"alias"`

	// First
	First int `json:"first"`

	// Second
	Second int `json:"second"`
}

// Response message
//
// swagger:response getSTHConsistencyResponse
type getSTHConsistencyResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Consistency []string `json:"consistency"`
	}
}

// Request message
//
// swagger:parameters getProofByHashRequest
type getProofByHashRequest struct { // nolint: unused,deadcode
	// Alias
	//
	// in: path
	// required: true
	Alias string `json:"alias"`

	// Hash
	Hash string `json:"hash"`

	// Tree size
	TreeSize int `json:"tree_size"`
}

// Response message
//
// swagger:response getProofByHashResponse
type getProofByHashResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		LeafIndex int64    `json:"leaf_index"`
		AuditPath []string `json:"audit_path"`
	}
}

// Request message
//
// swagger:parameters getEntriesRequest
type getEntriesRequest struct { // nolint: unused,deadcode
	// Alias
	//
	// in: path
	// required: true
	Alias string `json:"alias"`

	// Start
	Start int `json:"start"`

	// End
	End int `json:"end"`
}

// Response message
//
// swagger:response getEntriesResponse
type getEntriesResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Entries []struct {
			LeafInput string `json:"leaf_input"`
			ExtraData string `json:"extra_data"`
		} `json:"entries"`
	}
}

// Request message
//
// swagger:parameters getEntryAndProofRequest
type getEntryAndProofRequest struct { // nolint: unused,deadcode
	// Alias
	//
	// in: path
	// required: true
	Alias string `json:"alias"`

	// LeafIndex
	LeafIndex int `json:"leaf_index"`

	// TreeSize
	TreeSize int `json:"tree_size"`
}

// Response message
//
// swagger:response getEntryAndProofResponse
type getEntryAndProofResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		LeafInput string   `json:"leaf_input"`
		ExtraData string   `json:"extra_data"`
		AuditPath []string `json:"audit_path"`
	}
}
