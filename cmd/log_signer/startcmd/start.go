/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/ceda464a95a36e37e16fb361a5e426877c49d450/cmd/
trillian_log_signer/main.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package startcmd runs the log signing code.
package startcmd //nolint: cyclop

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/trillian/cmd"
	"github.com/google/trillian/extension"
	"github.com/google/trillian/log"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/google/trillian/quota"
	"github.com/google/trillian/quota/etcd"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/util"
	"github.com/google/trillian/util/clock"
	"github.com/google/trillian/util/election"
	"github.com/google/trillian/util/election2"
	etcdelect "github.com/google/trillian/util/election2/etcd"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"

	"github.com/trustbloc/vct/cmd/internal/serverutil"
	postgresschema "github.com/trustbloc/vct/pkg/storage/postgres/schema"
)

// CMD struct.
type CMD struct {
	RPCEndpoint              string
	HTTPEndpoint             string
	HealthzTimeout           time.Duration
	TLSCertFile              string
	TLSKeyFile               string
	SequencerIntervalFlag    time.Duration
	ETCDHTTPService          string
	QuotaSystem              string
	BatchSizeFlag            int
	StorageSystem            string
	NumSeqFlag               int
	SequencerGuardWindowFlag time.Duration
	LockDir                  string
	ForceMaster              bool
	PREElectionPause         time.Duration
	QuotaIncreaseFactor      float64
	ConfigFile               string
	PGConnStr                string
	MasterHoldInterval       time.Duration
	MasterHoldJitter         time.Duration
}

// Start server.
func (s *CMD) Start() error { //nolint:funlen
	if s.ConfigFile != "" {
		if err := cmd.ParseFlagFile(s.ConfigFile); err != nil {
			return fmt.Errorf("failed to load flags from config file %q: %w", s.ConfigFile, err)
		}
	}

	mf := prometheus.MetricFactory{}

	if s.StorageSystem == "postgres" {
		if err := serverutil.ImportPostgres(string(postgresschema.SQL), s.PGConnStr, s.StorageSystem); err != nil {
			return fmt.Errorf("failed to load %s schema: %w", s.StorageSystem, err)
		}
	}

	sp, err := storage.NewProvider(s.StorageSystem, mf)
	if err != nil {
		return fmt.Errorf("failed to get storage provider: %w", err)
	}
	defer sp.Close() // nolint: errcheck

	var client *clientv3.Client

	const defaultDialTimeout = 5 * time.Second

	if servers := *etcd.Servers; servers != "" {
		if client, err = clientv3.New(clientv3.Config{
			Endpoints:   strings.Split(servers, ","),
			DialTimeout: defaultDialTimeout,
		}); err != nil {
			return fmt.Errorf("failed to connect to etcd at %v: %w", servers, err)
		}
		defer client.Close() // nolint: errcheck
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go util.AwaitSignal(ctx, cancel)

	hostname, _ := os.Hostname() // nolint: errcheck
	instanceID := fmt.Sprintf("%s.%d", hostname, os.Getpid())

	var electionFactory election2.Factory

	switch {
	case s.ForceMaster:
		electionFactory = election2.NoopFactory{}
	case client != nil:
		electionFactory = etcdelect.NewFactory(instanceID, client, s.LockDir)
	default:
		return fmt.Errorf("either --force_master or --etcd_servers must be supplied")
	}

	qm, err := quota.NewManager(s.QuotaSystem)
	if err != nil {
		return fmt.Errorf("error creating quota manager: %w", err)
	}

	registry := extension.Registry{
		AdminStorage:    sp.AdminStorage(),
		LogStorage:      sp.LogStorage(),
		ElectionFactory: electionFactory,
		QuotaManager:    qm,
		MetricFactory:   mf,
	}

	// Start HTTP server (optional)
	if s.HTTPEndpoint != "" {
		// Announce our endpoint to etcd if so configured.
		unannounceHTTP := serverutil.AnnounceSelf(ctx, client, s.ETCDHTTPService, s.HTTPEndpoint)
		defer unannounceHTTP()
	}

	// Start the sequencing loop, which will run until we terminate the process. This controls
	// both sequencing and signing.
	// TODO(Martin2112): Should respect read only mode and the flags in tree control etc
	log.QuotaIncreaseFactor = s.QuotaIncreaseFactor
	sequencerManager := log.NewSequencerManager(registry, s.SequencerGuardWindowFlag)
	info := log.OperationInfo{
		Registry:    registry,
		BatchSize:   s.BatchSizeFlag,
		NumWorkers:  s.NumSeqFlag,
		RunInterval: s.SequencerIntervalFlag,
		TimeSource:  clock.System,
		ElectionConfig: election.RunnerConfig{
			PreElectionPause:   s.PREElectionPause,
			MasterHoldInterval: s.MasterHoldInterval,
			MasterHoldJitter:   s.MasterHoldJitter,
			TimeSource:         clock.System,
		},
	}
	sequencerTask := log.NewOperationManager(info, sequencerManager)

	go sequencerTask.OperationLoop(ctx)

	m := serverutil.Main{
		RPCEndpoint:      s.RPCEndpoint,
		HTTPEndpoint:     s.HTTPEndpoint,
		TLSCertFile:      s.TLSCertFile,
		TLSKeyFile:       s.TLSKeyFile,
		StatsPrefix:      "logsigner",
		DBClose:          sp.Close,
		Registry:         registry,
		RegisterServerFn: func(s *grpc.Server, _ extension.Registry) error { return nil },
		IsHealthy:        sp.AdminStorage().CheckDatabaseAccessible,
		HealthyDeadline:  s.HealthzTimeout,
	}

	if err := m.Run(ctx); err != nil {
		return fmt.Errorf("server exited with error: %w", err)
	}

	return nil
}
