/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cucumber/godog"
	"github.com/google/trillian/merkle/rfc6962/hasher"

	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/rest"
)

//go:embed testdata/*.json
var fs embed.FS // nolint: gochecknoglobals

// Steps represents BDD test steps.
type Steps struct {
	endpoint string
	client   *http.Client
	state    struct {
		GetSTHResponse *command.GetSTHResponse
		LastEntries    []command.LeafEntry
	}
}

// New creates BDD test steps instance.
func New() *Steps {
	return &Steps{client: &http.Client{Timeout: time.Minute}}
}

// RegisterSteps registers the BDD steps on the suite.
func (s *Steps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`VCT agent is running on "([^"]*)"$`, s.setEndpoint)
	suite.Step(`Add verifiable credential "([^"]*)" to Log$`, s.addVC)
	suite.Step(`Retrieve latest signed tree head and check that tree_size is "([^"]*)"$`, s.getSTH)
	suite.Step(`Retrieve merkle consistency proof between signed tree heads$`, s.getSTHConsistency)
	suite.Step(`Retrieve entries from log and check that len is "([^"]*)"$`, s.getEntries)
	suite.Step(`Retrieve merkle audit proof from log by leaf hash for entry "([^"]*)"$`, s.getProofByHash)
}

func (s *Steps) setEndpoint(endpoint string) error {
	s.endpoint = endpoint

	resp, err := s.getSTHAPI()

	s.state.GetSTHResponse = resp

	return err
}

func (s *Steps) addVC(file string) error {
	src, err := readFile(file)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, s.endpoint+rest.AddVCPath, bytes.NewBuffer(src),
	)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("client do: %w", err)
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	return getError(resp.Body)
}

func (s *Steps) getProofByHash(idx string) error {
	id, err := strconv.Atoi(idx)
	if err != nil {
		return fmt.Errorf("parse index: %w", err)
	}

	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.getSTHAPI()
		if err != nil {
			return err
		}

		entries, err := s.getProofByHashAPI(
			base64.StdEncoding.EncodeToString(hasher.DefaultHasher.HashLeaf(s.state.LastEntries[id-1].LeafInput)),
			resp.TreeSize,
		)
		if err != nil {
			return err
		}

		if len(entries.AuditPath) < 1 {
			return fmt.Errorf("no audit, expected greater than zero, got %d", len(entries.AuditPath))
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 15))
}

func (s *Steps) getEntries(lengths string) error {
	return backoff.Retry(func() error { // nolint: wrapcheck
		resp, err := s.getSTHAPI()
		if err != nil {
			return err
		}

		entries, err := s.getEntriesAPI(s.state.GetSTHResponse.TreeSize, resp.TreeSize)
		if err != nil {
			return err
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
		resp, err := s.getSTHAPI()
		if err != nil {
			return err
		}

		consistency, err := s.getSTHConsistencyAPI(s.state.GetSTHResponse.TreeSize, resp.TreeSize)
		if err != nil {
			return err
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
		resp, err := s.getSTHAPI()
		if err != nil {
			return err
		}

		ts := strconv.Itoa(int(resp.TreeSize - s.state.GetSTHResponse.TreeSize))
		if ts != treeSize {
			return fmt.Errorf("expected tree size %s, got %s", treeSize, ts)
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 15))
}

func getError(reader io.Reader) error {
	errMsg := struct {
		Message string `json:"message"`
	}{}

	if err := json.NewDecoder(reader).Decode(&errMsg); err != nil {
		return fmt.Errorf("json decode errMsg: %w", err)
	}

	return errors.New(errMsg.Message)
}

func readFile(msgFile string) ([]byte, error) {
	return fs.ReadFile(filepath.Clean(strings.Join([]string{ // nolint: wrapcheck
		"testdata", msgFile,
	}, string(filepath.Separator))))
}

func (s *Steps) getProofByHashAPI(hash string, treeSize uint64) (*command.GetProofByHashResponse, error) {
	params := url.Values{}
	params.Add("hash", hash)
	params.Add("tree_size", strconv.Itoa(int(treeSize)))

	apiPath := s.endpoint + rest.GetProofByHashPath + "?" + params.Encode()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiPath, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client do: %w", err)
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, getError(resp.Body)
	}

	var result *command.GetProofByHashResponse

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("json decode GetProofByHashResponse: %w", err)
	}

	return result, nil
}

func (s *Steps) getEntriesAPI(start, end uint64) (*command.GetEntriesResponse, error) {
	apiPath := s.endpoint + rest.GetEntriesPath + fmt.Sprintf("?start=%d&end=%d", start, end)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiPath, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client do: %w", err)
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, getError(resp.Body)
	}

	var result *command.GetEntriesResponse

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("json decode GetSTHConsistencyResponse: %w", err)
	}

	return result, nil
}

func (s *Steps) getSTHConsistencyAPI(first, second uint64) (*command.GetSTHConsistencyResponse, error) {
	apiPath := s.endpoint + rest.GetSTHConsistencyPath + fmt.Sprintf("?first=%d&second=%d", first, second)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiPath, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client do: %w", err)
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, getError(resp.Body)
	}

	var result *command.GetSTHConsistencyResponse

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("json decode GetSTHConsistencyResponse: %w", err)
	}

	return result, nil
}

func (s *Steps) getSTHAPI() (*command.GetSTHResponse, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.endpoint+rest.GetSTHPath, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client do: %w", err)
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, getError(resp.Body)
	}

	var result *command.GetSTHResponse

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("json decode GetSTHResponse: %w", err)
	}

	return result, nil
}
