/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"
)

//go:embed testdata/*.json
var fs embed.FS // nolint: gochecknoglobals

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
	suite.Step(`VCT agent is running on "([^"]*)"$`, s.setVCTClient)
	suite.Step(`Add verifiable credential "([^"]*)" to Log$`, s.addVC)
	suite.Step(`Retrieve latest signed tree head and check that tree_size is "([^"]*)"$`, s.getSTH)
	suite.Step(`Retrieve merkle consistency proof between signed tree heads$`, s.getSTHConsistency)
	suite.Step(`Retrieve entries from log and check that len is "([^"]*)"$`, s.getEntries)
	suite.Step(`Use timestamp from "([^"]*)" for "([^"]*)"$`, s.setTimestamp)
	suite.Step(`Retrieve merkle audit proof from log by leaf hash for "([^"]*)"$`, s.getProofByHash)
}

func (s *Steps) setVCTClient(endpoint string) error {
	s.vct = vct.New(endpoint, vct.WithHTTPClient(s.client))

	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.vct.GetSTH(context.Background())

		s.state.GetSTHResponse = resp

		return err // nolint: wrapcheck
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 60))
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

	pubKey, err := s.vct.GetPublicKey(context.Background())
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	vc, err := verifiable.ParseCredential(src,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithNoCustomSchemaCheck(),
		verifiable.WithJSONLDDocumentLoader(getLoader()),
	)
	if err != nil {
		return fmt.Errorf("parse credential: %w", err)
	}

	err = vct.VerifyVCTimestampSignature(resp.Signature, pubKey, resp.Timestamp, vc)
	if err != nil {
		return fmt.Errorf("verify VC Timestamp signature: %w", err)
	}

	s.state.AddedCredentials[file] = resp

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

	vc, err := verifiable.ParseCredential(src,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithNoCustomSchemaCheck(),
		verifiable.WithJSONLDDocumentLoader(getLoader()),
	)
	if err != nil {
		return fmt.Errorf("parse credential: %w", err)
	}

	hash, err := vct.CalculateLeafHash(s.state.AddedCredentials[file].Timestamp, vc)
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

func getLoader() *jsonld.DocumentLoader {
	loader, err := jsonld.NewDocumentLoader(mem.NewProvider(),
		jsonld.WithRemoteDocumentLoader(ld.NewDefaultDocumentLoader(&http.Client{})),
	)
	if err != nil {
		panic(err)
	}

	return loader
}

func readFile(msgFile string) ([]byte, error) {
	return fs.ReadFile(filepath.Clean(strings.Join([]string{ // nolint: wrapcheck
		"testdata", msgFile,
	}, string(filepath.Separator))))
}
