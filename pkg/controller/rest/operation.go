/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/errors"
)

var logger = log.New("controller/rest")

// API endpoints.
const (
	basePath              = "/ct/v1"
	AddVCPath             = basePath + "/add-vc"
	GetSTHPath            = basePath + "/get-sth"
	GetSTHConsistencyPath = basePath + "/get-sth-consistency"
	GetProofByHashPath    = basePath + "/get-proof-by-hash"
	GetEntriesPath        = basePath + "/get-entries"
	GetIssuersPath        = basePath + "/get-issuers"
	GetEntryAndProofPath  = basePath + "/get-entry-and-proof"
	GetPublicKeyPath      = basePath + "/get-public-key"
	HealthCheckPath       = "/healthcheck"
)

const (
	contentType     = "Content-Type"
	applicationJSON = "application/json"
)

// Cmd defines command methods.
type Cmd interface {
	AddVC(io.Writer, io.Reader) error
	GetIssuers(io.Writer, io.Reader) error
	GetSTH(io.Writer, io.Reader) error
	GetSTHConsistency(io.Writer, io.Reader) error
	GetProofByHash(io.Writer, io.Reader) error
	GetEntries(io.Writer, io.Reader) error
	GetEntryAndProof(io.Writer, io.Reader) error
	GetPublicKey(io.Writer, io.Reader) error
}

// Operation represents REST API controller.
type Operation struct {
	cmd Cmd
}

// New returns REST API controller.
func New(cmd Cmd) *Operation {
	return &Operation{cmd: cmd}
}

// GetRESTHandlers returns list of all handlers supported by this controller.
func (c *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		NewHTTPHandler(AddVCPath, http.MethodPost, c.AddVC),
		NewHTTPHandler(GetSTHPath, http.MethodGet, c.GetSTH),
		NewHTTPHandler(GetSTHConsistencyPath, http.MethodGet, c.GetSTHConsistency),
		NewHTTPHandler(GetProofByHashPath, http.MethodGet, c.GetProofByHash),
		NewHTTPHandler(GetEntriesPath, http.MethodGet, c.GetEntries),
		NewHTTPHandler(GetIssuersPath, http.MethodGet, c.GetIssuers),
		NewHTTPHandler(GetPublicKeyPath, http.MethodGet, c.GetPublicKey),
		NewHTTPHandler(GetEntryAndProofPath, http.MethodGet, c.GetEntryAndProof),
		NewHTTPHandler(HealthCheckPath, http.MethodGet, c.HealthCheck),
	}
}

// AddVC adds verifiable credential to log.
func (c *Operation) AddVC(w http.ResponseWriter, r *http.Request) {
	execute(c.cmd.AddVC, w, r.Body)
}

// GetSTH retrieves latest signed tree head.
func (c *Operation) GetSTH(w http.ResponseWriter, _ *http.Request) {
	execute(c.cmd.GetSTH, w, nil)
}

// GetIssuers returns issuers.
func (c *Operation) GetIssuers(w http.ResponseWriter, _ *http.Request) {
	execute(c.cmd.GetIssuers, w, nil)
}

// HealthCheck returns status.
func (c *Operation) HealthCheck(w http.ResponseWriter, _ *http.Request) {
	execute(func(rw io.Writer, req io.Reader) error {
		return json.NewEncoder(rw).Encode(map[string]interface{}{ // nolint: wrapcheck
			"status":       "success",
			"current_time": time.Now(),
		})
	}, w, nil)
}

// GetPublicKey returns public key.
func (c *Operation) GetPublicKey(w http.ResponseWriter, _ *http.Request) {
	execute(c.cmd.GetPublicKey, w, nil)
}

// GetSTHConsistency retrieves merkle consistency proofs between signed tree heads.
func (c *Operation) GetSTHConsistency(w http.ResponseWriter, r *http.Request) {
	const (
		firstParamName  = "first"
		secondParamName = "second"
	)

	first, err := strconv.ParseInt(r.FormValue(firstParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, firstParamName))

		return
	}

	second, err := strconv.ParseInt(r.FormValue(secondParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, secondParamName))

		return
	}

	req, err := json.Marshal(command.GetSTHConsistencyRequest{
		FirstTreeSize:  first,
		SecondTreeSize: second,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetSTHConsistency request: %w", err))

		return
	}

	execute(c.cmd.GetSTHConsistency, w, bytes.NewBuffer(req))
}

// GetProofByHash retrieves Merkle Audit proof from Log by leaf hash.
func (c *Operation) GetProofByHash(w http.ResponseWriter, r *http.Request) {
	const (
		hashParamName     = "hash"
		treeSizeParamName = "tree_size"
	)

	treeSize, err := strconv.ParseInt(r.FormValue(treeSizeParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, treeSizeParamName))

		return
	}

	req, err := json.Marshal(command.GetProofByHashRequest{
		Hash:     r.FormValue(hashParamName),
		TreeSize: treeSize,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetProofByHash request: %w", err))

		return
	}

	execute(c.cmd.GetProofByHash, w, bytes.NewBuffer(req))
}

// GetEntries retrieves entries from log.
func (c *Operation) GetEntries(w http.ResponseWriter, r *http.Request) {
	const (
		startParamName = "start"
		endParamName   = "end"
	)

	start, err := strconv.ParseInt(r.FormValue(startParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, startParamName))

		return
	}

	end, err := strconv.ParseInt(r.FormValue(endParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, endParamName))

		return
	}

	req, err := json.Marshal(command.GetEntriesRequest{
		Start: start,
		End:   end,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetEntries request: %w", err))

		return
	}

	execute(c.cmd.GetEntries, w, bytes.NewBuffer(req))
}

// GetEntryAndProof retrieves entry and merkle audit proof from log.
func (c *Operation) GetEntryAndProof(w http.ResponseWriter, r *http.Request) {
	const (
		leafIndexParamName = "leaf_index"
		treeSizeParamName  = "tree_size"
	)

	leafIndex, err := strconv.ParseInt(r.FormValue(leafIndexParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, leafIndexParamName))

		return
	}

	treeSize, err := strconv.ParseInt(r.FormValue(treeSizeParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, treeSizeParamName))

		return
	}

	req, err := json.Marshal(command.GetEntryAndProofRequest{
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetEntryAndProof request: %w", err))

		return
	}

	execute(c.cmd.GetEntryAndProof, w, bytes.NewBuffer(req))
}

func execute(exec command.Exec, rw http.ResponseWriter, req io.Reader) {
	rw.Header().Set(contentType, applicationJSON)

	if err := exec(rw, req); err != nil {
		sendError(rw, err)
	}
}

// ErrorResponse represents REST error message.
type ErrorResponse struct {
	Message string `json:"message"`
}

func sendError(rw http.ResponseWriter, e error) {
	rw.WriteHeader(errors.StatusCodeFromError(e))

	if err := json.NewEncoder(rw).Encode(ErrorResponse{Message: e.Error()}); err != nil {
		logger.Errorf("send error response: %v", e)
	}
}
