/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/trustbloc/edge-core/pkg/log"

	vcldcontext "github.com/trustbloc/vct/internal/pkg/ldcontext"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"
)

var logger = log.New("vct/bdd")

const contextsDir = "testdata"

// nolint: gochecknoglobals
var (
	//go:embed testdata/ld-*.json
	fsContext embed.FS

	//go:embed testdata/**/*.json
	fs embed.FS
)

// Steps represents BDD test steps.
type Steps struct {
	client *http.Client
	vct    *vct.Client
	state  state
}

type state struct {
	GetSTHResponse   *command.GetSTHResponse
	LastEntries      []command.LeafEntry
	AddedCredentials map[string]*command.AddVCResponse
}

// New creates BDD test steps instance.
func New() *Steps {
	return &Steps{
		client: &http.Client{Timeout: time.Minute},
		state:  state{AddedCredentials: map[string]*command.AddVCResponse{}},
	}
}

// RegisterSteps registers the BDD steps on the suite.
func (s *Steps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`VCT agent with ledger "([^"]*)" is running on "([^"]*)"$`, s.setVCTClient)
	suite.Step(`Add verifiable credential "([^"]*)" to Log$`, s.addVC)
	suite.Step(`No permissions to write$`, s.noWritePerm)
	suite.Step(`No permissions to read$`, s.noReadPerm)
	suite.Step(`Retrieve latest signed tree head and check that tree_size is "([^"]*)"$`, s.getSTH)
	suite.Step(`Retrieve merkle consistency proof between signed tree heads$`, s.getSTHConsistency)
	suite.Step(`Retrieve entries from log and check that len is "([^"]*)"$`, s.getEntries)
	suite.Step(`Use timestamp from "([^"]*)" for "([^"]*)"$`, s.setTimestamp)
	suite.Step(`Retrieve merkle audit proof from log by leaf hash for "([^"]*)"$`, s.getProofByHash)
	suite.Step(`The issuer "([^"]*)" is supported$`, s.issuerIsSupported)
	suite.Step(`The issuer "([^"]*)" is not supported$`, s.issuerIsNotSupported)
}

func (s *Steps) issuerIsSupported(issuer string) error {
	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.vct.GetIssuers(context.Background())
		if err != nil {
			return fmt.Errorf("get issuers: %w", err)
		}

		if len(resp) == 0 {
			return nil
		}

		for i := range resp {
			if resp[i] == issuer {
				return nil
			}
		}

		return fmt.Errorf("issuer %q is not supported", issuer)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 15))
}

func (s *Steps) issuerIsNotSupported(issuer string) error {
	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.vct.GetIssuers(context.Background())
		if err != nil {
			return fmt.Errorf("get issuers: %w", err)
		}

		if len(resp) == 0 {
			return fmt.Errorf("issuer %q is supported", issuer)
		}

		for i := range resp {
			if resp[i] == issuer {
				return fmt.Errorf("issuer %q is supported", issuer)
			}
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 15))
}

func (s *Steps) setVCTClient(ledgerURI, endpoint string) error {
	s.vct = vct.New(endpoint,
		vct.WithHTTPClient(s.client),
		vct.WithLedgerURI(ledgerURI),
		vct.WithAuthReadToken("tk1"),
		vct.WithAuthWriteToken("tk2"),
	)

	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.vct.GetSTH(context.Background())
		// ignores the error if it is a permission issue
		if err != nil && !strings.Contains(err.Error(), "action forbidden for") {
			return err
		}

		s.state.GetSTHResponse = resp

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 220))
}

func (s *Steps) noWritePerm() error {
	_, err := s.vct.AddVC(context.Background(), []byte(`{}`))
	if err == nil {
		return fmt.Errorf("credentials were successfully added")
	}

	if strings.Contains(err.Error(), "action forbidden for") {
		return nil
	}

	return err
}

func (s *Steps) noReadPerm() error {
	_, err := s.vct.GetIssuers(context.Background())
	if err == nil {
		return fmt.Errorf("retrieved issuers successfully")
	}

	if !strings.Contains(err.Error(), "action forbidden for") {
		return err
	}

	_, err = s.vct.GetSTH(context.Background())
	if err == nil {
		return fmt.Errorf("retrieved STH successfully")
	}

	if !strings.Contains(err.Error(), "action forbidden for") {
		return err
	}

	_, err = s.vct.GetSTHConsistency(context.Background(), 1, 2)
	if err == nil {
		return fmt.Errorf("retrieved STH Consistency successfully")
	}

	if !strings.Contains(err.Error(), "action forbidden for") {
		return err
	}

	_, err = s.vct.GetProofByHash(context.Background(), "", 1)
	if err == nil {
		return fmt.Errorf("retrieved proof by hash successfully")
	}

	if !strings.Contains(err.Error(), "action forbidden for") {
		return err
	}

	_, err = s.vct.GetEntries(context.Background(), 1, 2)
	if err == nil {
		return fmt.Errorf("retrieved entries successfully")
	}

	if !strings.Contains(err.Error(), "action forbidden for") {
		return err
	}

	_, err = s.vct.GetEntryAndProof(context.Background(), 1, 2)
	if err == nil {
		return fmt.Errorf("retrieved entry and proof successfully")
	}

	if !strings.Contains(err.Error(), "action forbidden for") {
		return err
	}

	return nil
}

func (s *Steps) addVC(file string) error {
	src, err := readFile(file)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	resp, err := s.vct.AddVC(context.Background(), src)
	if err != nil {
		return fmt.Errorf("add vc: %w", err)
	}

	webResp, err := s.vct.Webfinger(context.Background())
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	pubKey, err := base64.StdEncoding.DecodeString(webResp.Properties[command.PublicKeyType].(string))
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}

	err = vct.VerifyVCTimestampSignature(resp.Signature, pubKey, resp.Timestamp, src, getLoader())
	if err != nil {
		return fmt.Errorf("verify VC Timestamp signature: %w", err)
	}

	s.state.AddedCredentials[file] = resp

	logger.Infof("Successfully verified VC timestamp signature for VC %s - Signature: %s, Timestamp: %d, Public Key: %s",
		src, resp.Signature, resp.Timestamp, webResp.Properties[command.PublicKeyType])

	return nil
}

func (s *Steps) setTimestamp(from, to string) error {
	s.state.AddedCredentials[to] = s.state.AddedCredentials[from]

	return nil
}

func (s *Steps) getProofByHash(file string) error {
	src, err := readFile(file)
	if err != nil {
		return err
	}

	hash, err := vct.CalculateLeafHash(s.state.AddedCredentials[file].Timestamp, src, getLoader())
	if err != nil {
		return fmt.Errorf("calculate leaf hash from bytes: %w", err)
	}

	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.vct.GetSTH(context.Background())
		if err != nil {
			return fmt.Errorf("get STH: %w", err)
		}

		entries, err := s.vct.GetProofByHash(context.Background(), hash, resp.TreeSize)
		if err != nil {
			return fmt.Errorf("get proof by hash: %w", err)
		}

		if resp.TreeSize > 1 && len(entries.AuditPath) < 1 {
			return fmt.Errorf("no audit, expected greater than zero, got %d", len(entries.AuditPath))
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 15))
}

func (s *Steps) getEntries(lengths string) error {
	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.vct.GetSTH(context.Background())
		if err != nil {
			return fmt.Errorf("get STH: %w", err)
		}

		entries, err := s.vct.GetEntries(context.Background(), s.state.GetSTHResponse.TreeSize, resp.TreeSize)
		if err != nil {
			return fmt.Errorf("get entries: %w", err)
		}

		entriesLen := strconv.Itoa(len(entries.Entries))
		if entriesLen != lengths {
			return fmt.Errorf("no entries, expected %s, got %s", lengths, entriesLen)
		}

		s.state.LastEntries = entries.Entries

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 15))
}

func (s *Steps) getSTHConsistency() error {
	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.vct.GetSTH(context.Background())
		if err != nil {
			return fmt.Errorf("get STH: %w", err)
		}

		consistency, err := s.vct.GetSTHConsistency(
			context.Background(),
			s.state.GetSTHResponse.TreeSize,
			resp.TreeSize,
		)
		if err != nil {
			return fmt.Errorf("get STH consistency: %w", err)
		}

		if s.state.GetSTHResponse.TreeSize != 0 && len(consistency.Consistency) < 1 {
			return fmt.Errorf("no hash, expected greater than zero, got %d", len(consistency.Consistency))
		}

		if s.state.GetSTHResponse.TreeSize == 0 && len(consistency.Consistency) != 0 {
			return fmt.Errorf("empty hash expected, got %d", len(consistency.Consistency))
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 15))
}

func (s *Steps) getSTH(treeSize string) error {
	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.vct.GetSTH(context.Background())
		if err != nil {
			return fmt.Errorf("get STH: %w", err)
		}

		ts := strconv.Itoa(int(resp.TreeSize - s.state.GetSTHResponse.TreeSize))
		if ts != treeSize {
			return fmt.Errorf("expected tree size %s, got %s", treeSize, ts)
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 15))
}

func readFile(msgFile string) ([]byte, error) {
	return fs.ReadFile(filepath.Clean(strings.Join([]string{ // nolint: wrapcheck
		"testdata", msgFile,
	}, string(filepath.Separator))))
}

type provider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *provider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *provider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

func getLoader() *ld.DocumentLoader {
	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	if err != nil {
		panic(fmt.Errorf("create JSON-LD context store: %w", err))
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	if err != nil {
		panic(fmt.Errorf("create remote provider store: %w", err))
	}

	p := &provider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	ctx := vcldcontext.MustGetAll()

	ctx = append(ctx, getAll()...)

	documentLoader, err := ld.NewDocumentLoader(p,
		ld.WithExtraContexts(ctx...),
	)
	if err != nil {
		panic(err)
	}

	return documentLoader
}

// getAll returns all predefined contexts.
func getAll() []ldcontext.Document {
	var entries []os.DirEntry

	var contexts []ldcontext.Document

	entries, errOnce := fsContext.ReadDir(contextsDir)
	if errOnce != nil {
		panic(errOnce)
	}

	for _, entry := range entries {
		var file os.FileInfo

		file, errOnce = entry.Info()
		if errOnce != nil {
			panic(errOnce)
		}

		var content []byte
		// Do not use os.PathSeparator here, we are using go:embed to load files.
		// The path separator is a forward slash, even on Windows systems.
		content, errOnce = fsContext.ReadFile(contextsDir + "/" + file.Name())
		if errOnce != nil {
			panic(errOnce)
		}

		var doc ldcontext.Document

		errOnce = json.Unmarshal(content, &doc)
		if errOnce != nil {
			panic(errOnce)
		}

		contexts = append(contexts, doc)
	}

	return append(contexts[:0:0], contexts...)
}
