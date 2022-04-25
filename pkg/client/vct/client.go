/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vct

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"

	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/rest"
)

type clientOptions struct {
	http           HTTPClient
	authReadToken  string
	authWriteToken string
}

// ClientOpt represents client option func.
type ClientOpt func(*clientOptions)

// WithHTTPClient allows providing HTTP client.
func WithHTTPClient(client HTTPClient) ClientOpt {
	return func(o *clientOptions) {
		o.http = client
	}
}

// WithAuthReadToken add auth token.
func WithAuthReadToken(authToken string) ClientOpt {
	return func(o *clientOptions) {
		o.authReadToken = authToken
	}
}

// WithAuthWriteToken add auth token.
func WithAuthWriteToken(authToken string) ClientOpt {
	return func(o *clientOptions) {
		o.authWriteToken = authToken
	}
}

// HTTPClient represents HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client represents VCT REST client.
type Client struct {
	endpoint       string
	http           HTTPClient
	authReadToken  string
	authWriteToken string
}

// New returns VCT REST client.
func New(endpoint string, opts ...ClientOpt) *Client {
	op := &clientOptions{http: &http.Client{
		Timeout: time.Minute,
	}}

	for _, fn := range opts {
		fn(op)
	}

	return &Client{
		endpoint:       endpoint,
		http:           op.http,
		authReadToken:  op.authReadToken,
		authWriteToken: op.authWriteToken,
	}
}

// AddVC adds verifiable credential to log.
func (c *Client) AddVC(ctx context.Context, credential []byte) (*command.AddVCResponse, error) {
	var result *command.AddVCResponse
	if err := c.do(ctx, rest.AddVCPath, &result, withMethod(http.MethodPost), withBody(credential),
		withToken(c.authWriteToken)); err != nil {
		return nil, fmt.Errorf("add VC: %w", err)
	}

	return result, nil
}

// HealthCheck check health.
func (c *Client) HealthCheck(ctx context.Context) error {
	return c.do(ctx, rest.HealthCheckPath, &map[string]interface{}{}, withMethod(http.MethodGet),
		withToken(c.authReadToken))
}

// Webfinger returns discovery info.
func (c *Client) Webfinger(ctx context.Context) (*command.WebFingerResponse, error) {
	var result *command.WebFingerResponse
	if err := c.do(ctx, rest.WebfingerPath, &result, withToken(c.authReadToken)); err != nil {
		return nil, fmt.Errorf("webfinger: %w", err)
	}

	return result, nil
}

// GetIssuers returns issuers.
func (c *Client) GetIssuers(ctx context.Context) ([]string, error) {
	var result []string
	if err := c.do(ctx, rest.GetIssuersPath, &result, withToken(c.authReadToken)); err != nil {
		return nil, fmt.Errorf("get issuers: %w", err)
	}

	return result, nil
}

// GetSTH retrieves latest signed tree head.
func (c *Client) GetSTH(ctx context.Context) (*command.GetSTHResponse, error) {
	var result *command.GetSTHResponse
	if err := c.do(ctx, rest.GetSTHPath, &result, withToken(c.authReadToken)); err != nil {
		return nil, fmt.Errorf("get STH: %w", err)
	}

	return result, nil
}

// GetSTHConsistency retrieves merkle consistency proofs between signed tree heads.
func (c *Client) GetSTHConsistency(ctx context.Context, first, second uint64) (*command.GetSTHConsistencyResponse, error) { // nolint: lll
	const (
		firstParamName  = "first"
		secondParamName = "second"
	)

	opts := []opt{
		withValueAdd(firstParamName, strconv.FormatUint(first, 10)),
		withValueAdd(secondParamName, strconv.FormatUint(second, 10)),
		withToken(c.authReadToken),
	}

	var result *command.GetSTHConsistencyResponse
	if err := c.do(ctx, rest.GetSTHConsistencyPath, &result, opts...); err != nil {
		return nil, fmt.Errorf("get STH consistency: %w", err)
	}

	return result, nil
}

// GetProofByHash retrieves Merkle Audit proof from Log by leaf hash.
func (c *Client) GetProofByHash(ctx context.Context, hash string, treeSize uint64) (*command.GetProofByHashResponse, error) { // nolint: lll
	const (
		hashParamName     = "hash"
		treeSizeParamName = "tree_size"
	)

	opts := []opt{
		withValueAdd(hashParamName, hash),
		withValueAdd(treeSizeParamName, strconv.FormatUint(treeSize, 10)),
		withToken(c.authReadToken),
	}

	var result *command.GetProofByHashResponse
	if err := c.do(ctx, rest.GetProofByHashPath, &result, opts...); err != nil {
		return nil, fmt.Errorf("get proof by hash: %w", err)
	}

	return result, nil
}

// GetEntries retrieves entries from log.
func (c *Client) GetEntries(ctx context.Context, start, end uint64) (*command.GetEntriesResponse, error) {
	const (
		startParamName = "start"
		endParamName   = "end"
	)

	opts := []opt{
		withValueAdd(startParamName, strconv.FormatUint(start, 10)),
		withValueAdd(endParamName, strconv.FormatUint(end, 10)),
		withToken(c.authReadToken),
	}

	var result *command.GetEntriesResponse
	if err := c.do(ctx, rest.GetEntriesPath, &result, opts...); err != nil {
		return nil, fmt.Errorf("get entries: %w", err)
	}

	return result, nil
}

// GetEntryAndProof retrieves entry and merkle audit proof from log.
func (c *Client) GetEntryAndProof(ctx context.Context, leafIndex, treeSize uint64) (*command.GetEntryAndProofResponse, error) { // nolint: lll
	const (
		leafIndexParamName = "leaf_index"
		treeSizeParamName  = "tree_size"
	)

	opts := []opt{
		withValueAdd(leafIndexParamName, strconv.FormatUint(leafIndex, 10)),
		withValueAdd(treeSizeParamName, strconv.FormatUint(treeSize, 10)),
		withToken(c.authReadToken),
	}

	var result *command.GetEntryAndProofResponse
	if err := c.do(ctx, rest.GetEntryAndProofPath, &result, opts...); err != nil {
		return nil, fmt.Errorf("get entry and proof: %w", err)
	}

	return result, nil
}

// CalculateLeafHash calculates hash for given credentials.
func CalculateLeafHash(timestamp uint64, vc *verifiable.Credential) (string, error) {
	leaf, err := command.CreateLeaf(timestamp, vc)
	if err != nil {
		return "", fmt.Errorf("create leaf: %w", err)
	}

	leafData, err := json.Marshal(leaf)
	if err != nil {
		return "", fmt.Errorf("marshal leaf: %w", err)
	}

	return base64.StdEncoding.EncodeToString(hasher.DefaultHasher.HashLeaf(leafData)), nil
}

// VerifyVCTimestampSignature verifies VC timestamp signature.
func VerifyVCTimestampSignature(signature, pubKey []byte, timestamp uint64, vc *verifiable.Credential) error {
	var sig *command.DigitallySigned

	if err := json.Unmarshal(signature, &sig); err != nil {
		return fmt.Errorf("unmarshal signature: %w", err)
	}

	leaf, err := command.CreateLeaf(timestamp, vc)
	if err != nil {
		return fmt.Errorf("create leaf: %w", err)
	}

	data, err := json.Marshal(command.CreateVCTimestampSignature(leaf))
	if err != nil {
		return fmt.Errorf("marshal VC timestamp signature: %w", err)
	}

	kh, err := (&localkms.LocalKMS{}).PubKeyBytesToHandle(pubKey, sig.Algorithm.Type)
	if err != nil {
		return fmt.Errorf("pub key to handle: %w", err)
	}

	return (&tinkcrypto.Crypto{}).Verify(sig.Signature, data, kh) // nolint: wrapcheck
}

type options struct {
	method string
	body   io.Reader
	values url.Values
	token  string
}

type opt func(*options)

func withBody(val []byte) opt {
	return func(o *options) {
		o.body = bytes.NewBuffer(val)
	}
}

func withValueAdd(key, val string) opt {
	return func(o *options) {
		o.values.Add(key, val)
	}
}

func withMethod(val string) opt {
	return func(o *options) {
		o.method = val
	}
}

func withToken(val string) opt {
	return func(o *options) {
		o.token = val
	}
}

func (c *Client) do(ctx context.Context, path string, v interface{}, opts ...opt) error {
	op := &options{method: http.MethodGet, values: url.Values{}}
	for _, fn := range opts {
		fn(op)
	}

	path = strings.Replace(path, rest.AliasPath, "", 1)

	req, err := http.NewRequestWithContext(ctx, op.method, c.endpoint+path+"?"+op.values.Encode(), op.body)
	if err != nil {
		return fmt.Errorf("new request with context: %w", err)
	}

	if op.token != "" {
		req.Header.Add("Authorization", "Bearer "+op.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != http.StatusOK {
		return getError(resp.Body)
	}

	return json.NewDecoder(resp.Body).Decode(&v) // nolint: wrapcheck
}

func getError(reader io.Reader) error {
	var errMsg *rest.ErrorResponse

	if err := json.NewDecoder(reader).Decode(&errMsg); err != nil {
		return fmt.Errorf("json decode ErrorResponse: %w", err)
	}

	return errors.New(errMsg.Message)
}
