/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd_test

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/vct/pkg/controller/errors"
	"github.com/trustbloc/vct/test/bdd/pkg/controller/rest"
)

var logger = log.New("vct/bdd")

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all
	tags := "all"

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" {
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	status := runBddTests(tags, format)
	if st := m.Run(); st > status {
		status = st
	}

	os.Exit(status)
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

// nolint: gochecknoglobals
var (
	dockerComposeUp   = []string{"docker-compose", "-f", "./fixtures/vct/docker-compose.yml", "up", "-d"}
	dockerComposeDown = []string{"docker-compose", "-f", "./fixtures/vct/docker-compose.yml", "down"}
	createTree        = []string{"make", "--no-print-directory", "createtree"}
)

func runBddTests(tags, format string) int {
	return godog.RunWithOptions("godogs", func(s *godog.Suite) {
		s.BeforeSuite(func() {
			logger.Infof("Running %s", strings.Join(dockerComposeUp, " "))
			if err := exec.Command(dockerComposeUp[0], dockerComposeUp[1:]...).Run(); err != nil { //nolint: gosec
				logger.Errorf("command %q failed: %w", strings.Join(dockerComposeUp, " "), err)
			}
		})
		s.BeforeSuite(func() {
			logger.Infof("Running %s", strings.Join(createTree, " "))
			err := backoff.Retry(func() error {
				resp, err := exec.Command(createTree[0], createTree[1:]...).CombinedOutput() //nolint: gosec
				if err != nil {
					return fmt.Errorf("command %q failed: %w", strings.Join(createTree, " "), err)
				}

				logID := strings.TrimSpace(string(resp))

				_, err = strconv.ParseInt(logID, 10, 64)
				if err != nil {
					return errors.New(string(resp)) // nolint: wrapcheck
				}

				logger.Infof("LogID was created %s", logID)

				if err = os.Setenv("VCT_LOG_ID", logID); err != nil {
					return fmt.Errorf("set env: %w", err)
				}

				return nil
			}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 60))
			if err != nil {
				logger.Errorf("create tree failed: %w", err)
			}
		})
		s.BeforeSuite(func() {
			logger.Infof("Running %s", strings.Join(dockerComposeUp, " "))
			if err := exec.Command(dockerComposeUp[0], dockerComposeUp[1:]...).Run(); err != nil { //nolint: gosec
				logger.Errorf("command %q failed: %w", strings.Join(dockerComposeUp, " "), err)
			}
		})
		s.AfterSuite(func() {
			logger.Infof("Running %s", strings.Join(dockerComposeDown, " "))
			if err := exec.Command(dockerComposeDown[0], dockerComposeDown[1:]...).Run(); err != nil { //nolint: gosec
				logger.Errorf("command %q failed: %w", strings.Join(dockerComposeDown, " "), err)
			}
		})
		featureContext(s)
	}, godog.Options{
		Tags:          tags,
		Format:        format,
		Paths:         []string{"features"},
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	})
}

func featureContext(s *godog.Suite) {
	rest.New().RegisterSteps(s)
}
