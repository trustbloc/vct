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

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/errors"
)

var logger = log.New("controller/rest")

// API endpoints.
const (
	aliasVarName          = "alias"
	AliasPath             = "/{" + aliasVarName + "}"
	basePath              = AliasPath + "/v1"
	AddVCPath             = basePath + "/add-vc"
	GetSTHPath            = basePath + "/get-sth"
	GetSTHConsistencyPath = basePath + "/get-sth-consistency"
	GetProofByHashPath    = basePath + "/get-proof-by-hash"
	GetEntriesPath        = basePath + "/get-entries"
	GetIssuersPath        = basePath + "/get-issuers"
	GetEntryAndProofPath  = basePath + "/get-entry-and-proof"
	WebfingerPath         = AliasPath + "/.well-known/webfinger"
	AddContextPath        = basePath + "/context/add"
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
	Webfinger(io.Writer, io.Reader) error
	AddLdContext(io.Writer, io.Reader) error
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
		NewHTTPHandler(WebfingerPath, http.MethodGet, c.Webfinger),
		NewHTTPHandler(GetEntryAndProofPath, http.MethodGet, c.GetEntryAndProof),
		NewHTTPHandler(HealthCheckPath, http.MethodGet, c.HealthCheck),
		// JSON-LD contexts API
		NewHTTPHandler(AddContextPath, http.MethodPost, c.AddLdContext),
	}
}

// AddLdContext swagger:route POST /{alias}/v1/context/add vct addLdContextRequest
//
// Adds jsonld context.
//
// Responses:
//    default: genericError
//        200: addLdContextResponse
func (c *Operation) AddLdContext(w http.ResponseWriter, r *http.Request) {
	var context bytes.Buffer

	_, err := io.Copy(&context, r.Body)
	if err != nil {
		sendError(w, fmt.Errorf("%w: copy context", errors.ErrInternal))

		return
	}

	req, err := json.Marshal(command.AddLdContextRequest{
		Alias:   mux.Vars(r)[aliasVarName],
		Context: context.Bytes(),
	})
	if err != nil {
		sendError(w, fmt.Errorf("%w: marshal AddLdContextRequest", errors.ErrInternal))

		return
	}

	execute(c.cmd.AddLdContext, w, bytes.NewBuffer(req))
}

// AddVC swagger:route POST /{alias}/v1/add-vc vct addVCRequest
//
// Adds verifiable credential to log.
//
// Responses:
//    default: genericError
//        200: addVCResponse
func (c *Operation) AddVC(w http.ResponseWriter, r *http.Request) {
	var vcEntry bytes.Buffer

	_, err := io.Copy(&vcEntry, r.Body)
	if err != nil {
		sendError(w, fmt.Errorf("%w: copy vc", errors.ErrInternal))

		return
	}

	req, err := json.Marshal(command.AddVCRequest{
		Alias:   mux.Vars(r)[aliasVarName],
		VCEntry: vcEntry.Bytes(),
	})
	if err != nil {
		sendError(w, fmt.Errorf("%w: marshal AddVCRequest", errors.ErrInternal))

		return
	}

	execute(c.cmd.AddVC, w, bytes.NewBuffer(req))
}

// GetSTH swagger:route GET /{alias}/v1/get-sth vct getSTHRequest
//
// Retrieves the latest signed tree head.
//
// Responses:
//    default: genericError
//        200: getSTHResponse
func (c *Operation) GetSTH(w http.ResponseWriter, r *http.Request) {
	execute(c.cmd.GetSTH, w, bytes.NewBufferString(fmt.Sprintf("%q", mux.Vars(r)[aliasVarName])))
}

// GetIssuers swagger:route GET /{alias}/v1/get-issuers vct getIssuersRequest
//
// Returns issuers.
//
// Responses:
//    default: genericError
//        200: getIssuersResponse
func (c *Operation) GetIssuers(w http.ResponseWriter, r *http.Request) {
	execute(c.cmd.GetIssuers, w, bytes.NewBufferString(fmt.Sprintf("%q", mux.Vars(r)[aliasVarName])))
}

// HealthCheck swagger:route GET /healthcheck vct healthCheckRequest
//
// Returns health check status.
//
// Responses:
//    default: genericError
//        200: healthCheckResponse
func (c *Operation) HealthCheck(w http.ResponseWriter, _ *http.Request) {
	execute(func(rw io.Writer, req io.Reader) error {
		return json.NewEncoder(rw).Encode(map[string]interface{}{ // nolint: wrapcheck
			"status":       "success",
			"current_time": time.Now(),
		})
	}, w, nil)
}

// Webfinger swagger:route GET /{alias}/.well-known/webfinger vct webfingerRequest
//
// Returns discovery info.
//
// Responses:
//    default: genericError
//        200: webfingerResponse
func (c *Operation) Webfinger(w http.ResponseWriter, r *http.Request) {
	execute(c.cmd.Webfinger, w, bytes.NewBufferString(fmt.Sprintf("%q", mux.Vars(r)[aliasVarName])))
}

// GetSTHConsistency swagger:route GET /{alias}/v1/get-sth-consistency vct getSTHConsistencyRequest
//
// Retrieves merkle consistency proofs between signed tree heads.
//
// Responses:
//    default: genericError
//        200: getSTHConsistencyResponse
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
		Alias:          mux.Vars(r)[aliasVarName],
		FirstTreeSize:  first,
		SecondTreeSize: second,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetSTHConsistency request: %w", err))

		return
	}

	execute(c.cmd.GetSTHConsistency, w, bytes.NewBuffer(req))
}

// GetProofByHash swagger:route GET /{alias}/v1/get-proof-by-hash vct getProofByHashRequest
//
// Retrieves Merkle Audit proof from Log by leaf hash.
//
// Responses:
//    default: genericError
//        200: getProofByHashResponse
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
		Alias:    mux.Vars(r)[aliasVarName],
		Hash:     r.FormValue(hashParamName),
		TreeSize: treeSize,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetProofByHash request: %w", err))

		return
	}

	execute(c.cmd.GetProofByHash, w, bytes.NewBuffer(req))
}

// GetEntries swagger:route GET /{alias}/v1/get-entries vct getEntriesRequest
//
// Retrieves entries from log.
//
// Responses:
//    default: genericError
//        200: getEntriesResponse
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
		Alias: mux.Vars(r)[aliasVarName],
		Start: start,
		End:   end,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetEntries request: %w", err))

		return
	}

	execute(c.cmd.GetEntries, w, bytes.NewBuffer(req))
}

// GetEntryAndProof swagger:route GET /{alias}/v1/get-entry-and-proof vct getEntryAndProofRequest
//
// Retrieves entry and merkle audit proof from log.
//
// Responses:
//    default: genericError
//        200: getEntryAndProofResponse
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
		Alias:     mux.Vars(r)[aliasVarName],
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
