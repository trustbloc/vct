/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cucumber/godog"

	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/rest"
)

// Steps represents BDD test steps.
type Steps struct {
	endpoint string
	client   *http.Client
	state    struct {
		GetSTHResponse *command.GetSTHResponse
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
}

func (s *Steps) setEndpoint(endpoint string) error {
	s.endpoint = endpoint

	resp, err := s.getSTHAPI()

	s.state.GetSTHResponse = resp

	return err
}

func (s *Steps) addVC(file string) error {
	src, err := getReader(file)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.endpoint+rest.AddVCPath, src)
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
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 10))
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

func getReader(msgFile string) (io.Reader, error) {
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("did not get a path")
	}

	fullPath := strings.Join([]string{filepath.Dir(path), "testdata", msgFile}, string(filepath.Separator))

	file, err := os.Open(filepath.Clean(fullPath))
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = file.Close() }() // nolint: errcheck

	buf := &bytes.Buffer{}

	_, err = io.Copy(buf, file)
	if err != nil {
		return nil, fmt.Errorf("copy: %w", err)
	}

	return buf, nil
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
