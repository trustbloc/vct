/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd_test

import (
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

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

const composeFile = "./fixtures/vct/docker-compose.yml"

// nolint: gochecknoglobals
var (
	dockerComposeUp   = []string{"docker-compose", "-f", composeFile, "up", "--force-recreate", "-d"}
	dockerComposeDown = []string{"docker-compose", "-f", composeFile, "down"}
)

func runBddTests(tags, format string) int {
	return godog.RunWithOptions("godogs", func(s *godog.Suite) {
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
