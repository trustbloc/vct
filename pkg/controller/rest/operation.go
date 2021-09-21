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
	"sync"
	"time"

	"github.com/google/trillian/monitoring"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/errors"
)

var logger = log.New("controller/rest")

// API endpoints.
const (
	aliasVarName          = "alias"
	AliasPath             = "/{" + aliasVarName + "}"
	BasePath              = AliasPath + "/v1"
	AddVCPath             = BasePath + "/add-vc"
	GetSTHPath            = BasePath + "/get-sth"
	GetSTHConsistencyPath = BasePath + "/get-sth-consistency"
	GetProofByHashPath    = BasePath + "/get-proof-by-hash"
	GetEntriesPath        = BasePath + "/get-entries"
	GetIssuersPath        = BasePath + "/get-issuers"
	GetEntryAndProofPath  = BasePath + "/get-entry-and-proof"
	WebfingerPath         = AliasPath + "/.well-known/webfinger"
	HealthCheckPath       = "/healthcheck"
	MetricsPath           = "/metrics"
)

const (
	contentType     = "Content-Type"
	applicationJSON = "application/json"
)

// nolint: gochecknoglobals
var (
	once                     sync.Once
	addVCCounter             monitoring.Counter
	addVCLatency             monitoring.Histogram
	getSTHCounter            monitoring.Counter
	getSTHLatency            monitoring.Histogram
	getSTHConsistencyCounter monitoring.Counter
	getSTHConsistencyLatency monitoring.Histogram
	getProofByHashCounter    monitoring.Counter
	getProofByHashLatency    monitoring.Histogram
	getEntriesCounter        monitoring.Counter
	getEntriesLatency        monitoring.Histogram
	getEntryAndProofCounter  monitoring.Counter
	getEntryAndProofLatency  monitoring.Histogram
	getIssuersCounter        monitoring.Counter
	getIssuersLatency        monitoring.Histogram
	webfingerCounter         monitoring.Counter
	webfingerLatency         monitoring.Histogram
)

// nolint: lll
func createMetrics(mf monitoring.MetricFactory) {
	addVCCounter = mf.NewCounter("add_vc", "Number of /add-vc operation", "alias")
	addVCLatency = mf.NewHistogram("add_vc_latency", "Latency of /add-vc operation in seconds", "alias")

	getSTHCounter = mf.NewCounter("get_sth", "Number of /get-sth operation", "alias")
	getSTHLatency = mf.NewHistogram("get_sth_latency", "Latency of /get-sth operation in seconds", "alias")

	getSTHConsistencyCounter = mf.NewCounter("get_sth_consistency", "Number of /get-sth-consistency operation", "alias")
	getSTHConsistencyLatency = mf.NewHistogram("get_sth_consistency_latency", "Latency of /get-sth-consistency operation in seconds", "alias")

	getProofByHashCounter = mf.NewCounter("get_proof_by_hash", "Number of /get-proof-by-hash operation", "alias")
	getProofByHashLatency = mf.NewHistogram("get_proof_by_hash_latency", "Latency of /get-proof-by-hash operation in seconds", "alias")

	getEntriesCounter = mf.NewCounter("get_entries", "Number of /get-entries operation", "alias")
	getEntriesLatency = mf.NewHistogram("get_entries_latency", "Latency of /get-entries operation in seconds", "alias")

	getEntryAndProofCounter = mf.NewCounter("get_entry_and_proof", "Number of /get-entry-and-proof operation", "alias")
	getEntryAndProofLatency = mf.NewHistogram("get_entry_and_proof_latency", "Latency of /get-entry-and-proof operation in seconds", "alias")

	getIssuersCounter = mf.NewCounter("get_issuers", "Number of /get-issuers operation", "alias")
	getIssuersLatency = mf.NewHistogram("get_issuers_latency", "Latency of /get-issuers operation in seconds", "alias")

	webfingerCounter = mf.NewCounter("webfinger", "Number of /webfinger operation", "alias")
	webfingerLatency = mf.NewHistogram("webfinger_latency", "Latency of /webfinger operation in seconds", "alias")
}

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
}

// Operation represents REST API controller.
type Operation struct {
	cmd Cmd
	mf  monitoring.MetricFactory
}

// New returns REST API controller.
func New(cmd Cmd, mf monitoring.MetricFactory) *Operation {
	if mf == nil {
		mf = monitoring.InertMetricFactory{}
	}

	once.Do(func() { createMetrics(mf) })

	return &Operation{cmd: cmd, mf: mf}
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
		// Metrics
		NewHTTPHandler(MetricsPath, http.MethodGet, c.metrics()),
	}
}

func (c *Operation) metrics() http.HandlerFunc {
	ph := promhttp.HandlerFor(prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	)

	return func(writer http.ResponseWriter, request *http.Request) {
		ph.ServeHTTP(writer, request)
	}
}

// AddVC swagger:route POST /{alias}/v1/add-vc vct addVCRequest
//
// Adds verifiable credential to log.
//
// Responses:
//    default: genericError
//        200: addVCResponse
func (c *Operation) AddVC(w http.ResponseWriter, r *http.Request) {
	var (
		start   = time.Now()
		vcEntry bytes.Buffer
	)

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

	execute(func(rw io.Writer, req io.Reader) error {
		if err := c.cmd.AddVC(rw, req); err != nil {
			return err
		}

		addVCCounter.Add(1, mux.Vars(r)[aliasVarName])
		addVCLatency.Observe(time.Since(start).Seconds(), mux.Vars(r)[aliasVarName])

		return nil
	}, w, bytes.NewBuffer(req))
}

// GetSTH swagger:route GET /{alias}/v1/get-sth vct getSTHRequest
//
// Retrieves the latest signed tree head.
//
// Responses:
//    default: genericError
//        200: getSTHResponse
func (c *Operation) GetSTH(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	execute(func(rw io.Writer, req io.Reader) error {
		if err := c.cmd.GetSTH(rw, req); err != nil {
			return err
		}

		getSTHCounter.Add(1, mux.Vars(r)[aliasVarName])
		getSTHLatency.Observe(time.Since(start).Seconds(), mux.Vars(r)[aliasVarName])

		return nil
	}, w, bytes.NewBufferString(fmt.Sprintf("%q", mux.Vars(r)[aliasVarName])))
}

// GetIssuers swagger:route GET /{alias}/v1/get-issuers vct getIssuersRequest
//
// Returns issuers.
//
// Responses:
//    default: genericError
//        200: getIssuersResponse
func (c *Operation) GetIssuers(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	execute(func(rw io.Writer, req io.Reader) error {
		if err := c.cmd.GetIssuers(rw, req); err != nil {
			return err
		}

		getIssuersCounter.Add(1, mux.Vars(r)[aliasVarName])
		getIssuersLatency.Observe(time.Since(start).Seconds(), mux.Vars(r)[aliasVarName])

		return nil
	}, w, bytes.NewBufferString(fmt.Sprintf("%q", mux.Vars(r)[aliasVarName])))
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
	start := time.Now()

	execute(func(rw io.Writer, req io.Reader) error {
		if err := c.cmd.Webfinger(rw, req); err != nil {
			return err
		}

		webfingerCounter.Add(1, mux.Vars(r)[aliasVarName])
		webfingerLatency.Observe(time.Since(start).Seconds(), mux.Vars(r)[aliasVarName])

		return nil
	}, w, bytes.NewBufferString(fmt.Sprintf("%q", mux.Vars(r)[aliasVarName])))
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

	start := time.Now()

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

	execute(func(rw io.Writer, req io.Reader) error {
		if err := c.cmd.GetSTHConsistency(rw, req); err != nil {
			return err
		}

		getSTHConsistencyCounter.Add(1, mux.Vars(r)[aliasVarName])
		getSTHConsistencyLatency.Observe(time.Since(start).Seconds(), mux.Vars(r)[aliasVarName])

		return nil
	}, w, bytes.NewBuffer(req))
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

	start := time.Now()

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

	execute(func(rw io.Writer, req io.Reader) error {
		if err := c.cmd.GetProofByHash(rw, req); err != nil {
			return err
		}

		getProofByHashCounter.Add(1, mux.Vars(r)[aliasVarName])
		getProofByHashLatency.Observe(time.Since(start).Seconds(), mux.Vars(r)[aliasVarName])

		return nil
	}, w, bytes.NewBuffer(req))
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

	startTime := time.Now()

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

	execute(func(rw io.Writer, req io.Reader) error {
		if err := c.cmd.GetEntries(rw, req); err != nil {
			return err
		}

		getEntriesCounter.Add(1, mux.Vars(r)[aliasVarName])
		getEntriesLatency.Observe(time.Since(startTime).Seconds(), mux.Vars(r)[aliasVarName])

		return nil
	}, w, bytes.NewBuffer(req))
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

	start := time.Now()

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

	execute(func(rw io.Writer, req io.Reader) error {
		if err := c.cmd.GetEntryAndProof(rw, req); err != nil {
			return err
		}

		getEntryAndProofCounter.Add(1, mux.Vars(r)[aliasVarName])
		getEntryAndProofLatency.Observe(time.Since(start).Seconds(), mux.Vars(r)[aliasVarName])

		return nil
	}, w, bytes.NewBuffer(req))
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
