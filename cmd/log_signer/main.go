/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/ceda464a95a36e37e16fb361a5e426877c49d450/cmd/trillian_log_signer/main.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// The log_signer binary runs the log signing code.
package main

import (
	"context"
	"flag"
	"fmt"

	// nolint:gosec
	_ "net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/google/trillian/cmd"
	"github.com/google/trillian/extension"
	"github.com/google/trillian/log"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/opencensus"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/google/trillian/quota"
	"github.com/google/trillian/quota/etcd"
	_ "github.com/google/trillian/quota/mysqlqm"
	"github.com/google/trillian/storage"
	_ "github.com/google/trillian/storage/cloudspanner"
	_ "github.com/google/trillian/storage/mysql"
	"github.com/google/trillian/util"
	"github.com/google/trillian/util/clock"
	"github.com/google/trillian/util/election"
	"github.com/google/trillian/util/election2"
	etcdelect "github.com/google/trillian/util/election2/etcd"
	arieslog "github.com/hyperledger/aries-framework-go/pkg/common/log"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"

	"github.com/trustbloc/vct/cmd/internal/serverutil"
	mysqlschema "github.com/trustbloc/vct/pkg/storage/mysql/schema"
	_ "github.com/trustbloc/vct/pkg/storage/postgres"
	postgresschema "github.com/trustbloc/vct/pkg/storage/postgres/schema"
)

var logger = arieslog.New("log-signer")

const (
	sequencerInterval         = 100 * time.Millisecond
	defaultHealthzTimeout     = 5 * time.Second
	defaultMasterHoldInterval = 60 * time.Second
	defaultMasterHoldJitter   = 120 * time.Second
)

// nolint: lll
var (
	rpcEndpoint              = flag.String("rpc_endpoint", "localhost:8090", "Endpoint for RPC requests (host:port)")
	httpEndpoint             = flag.String("http_endpoint", "localhost:8091", "Endpoint for HTTP (host:port, empty means disabled)")
	tlsCertFile              = flag.String("tls_cert_file", "", "Path to the TLS server certificate. If unset, the server will use unsecured connections.")
	tlsKeyFile               = flag.String("tls_key_file", "", "Path to the TLS server key. If unset, the server will use unsecured connections.")
	sequencerIntervalFlag    = flag.Duration("sequencer_interval", sequencerInterval, "Time between each sequencing pass through all logs")
	batchSizeFlag            = flag.Int("batch_size", 1000, "Max number of leaves to process per batch")
	numSeqFlag               = flag.Int("num_sequencers", 10, "Number of sequencer workers to run in parallel")
	sequencerGuardWindowFlag = flag.Duration("sequencer_guard_window", 0, "If set, the time elapsed before submitted leaves are eligible for sequencing")
	forceMaster              = flag.Bool("force_master", false, "If true, assume master for all logs")
	etcdHTTPService          = flag.String("etcd_http_service", "trillian-logsigner-http", "Service name to announce our HTTP endpoint under")
	lockDir                  = flag.String("lock_file_path", "/test/multimaster", "etcd lock file directory path")
	healthzTimeout           = flag.Duration("healthz_timeout", defaultHealthzTimeout, "Timeout used during healthz checks")

	quotaSystem         = flag.String("quota_system", "mysql", fmt.Sprintf("Quota system to use. One of: %v", quota.Providers()))
	quotaIncreaseFactor = flag.Float64("quota_increase_factor", log.QuotaIncreaseFactor,
		"Increase factor for tokens replenished by sequencing-based quotas"+
			" (1 means a 1:1 relationship between sequenced leaves and replenished tokens)."+
			"Only effective for --quota_system=etcd.")

	storageSystem = flag.String("storage_system", "mysql", fmt.Sprintf("Storage system to use. One of: %v", storage.Providers()))

	preElectionPause   = flag.Duration("pre_election_pause", 1*time.Second, "Maximum time to wait before starting elections")
	masterHoldInterval = flag.Duration("master_hold_interval", defaultMasterHoldInterval, "Minimum interval to hold mastership for")
	masterHoldJitter   = flag.Duration("master_hold_jitter", defaultMasterHoldJitter, "Maximal random addition to --master_hold_interval")

	configFile = flag.String("config", "", "Config file containing flags, file contents can be overridden by command line flags")

	_ = flag.String("import_conn_str", "", "Connection string for Postgres or MySQL database")
)

func main() { // nolint: funlen,cyclop
	flag.Parse()

	if *configFile != "" {
		if err := cmd.ParseFlagFile(*configFile); err != nil {
			logger.Fatalf("Failed to load flags from config file %q: %s", *configFile, err)
		}
	}

	logger.Infof("**** Log Signer Starting ****")

	mf := prometheus.MetricFactory{}

	monitoring.SetStartSpan(opencensus.StartSpan)

	if *storageSystem == "postgres" {
		if err := serverutil.ImportPostgres(string(postgresschema.SQL)); err != nil {
			logger.Fatalf("Failed to load %s schema: %v", *storageSystem, err)
		}
	}

	if *storageSystem == "mysql" {
		if err := serverutil.ImportMySQL(strings.Split(string(mysqlschema.SQL), ";")...); err != nil {
			logger.Fatalf("Failed to load %s schema: %v", *storageSystem, err)
		}
	}

	sp, err := storage.NewProvider(*storageSystem, mf)
	if err != nil {
		logger.Fatalf("Failed to get storage provider: %v", err)
	}
	defer sp.Close() // nolint: errcheck

	var client *clientv3.Client

	const defaultDialTimeout = 5 * time.Second

	if servers := *etcd.Servers; servers != "" {
		if client, err = clientv3.New(clientv3.Config{
			Endpoints:   strings.Split(servers, ","),
			DialTimeout: defaultDialTimeout,
		}); err != nil {
			logger.Fatalf("Failed to connect to etcd at %v: %v", servers, err)
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
	case *forceMaster:
		logger.Warnf("**** Acting as master for all logs ****")

		electionFactory = election2.NoopFactory{}
	case client != nil:
		electionFactory = etcdelect.NewFactory(instanceID, client, *lockDir)
	default:
		logger.Fatalf("Either --force_master or --etcd_servers must be supplied")
	}

	qm, err := quota.NewManager(*quotaSystem)
	if err != nil {
		logger.Fatalf("Error creating quota manager: %v", err)
	}

	registry := extension.Registry{
		AdminStorage:    sp.AdminStorage(),
		LogStorage:      sp.LogStorage(),
		ElectionFactory: electionFactory,
		QuotaManager:    qm,
		MetricFactory:   mf,
	}

	// Start HTTP server (optional)
	if *httpEndpoint != "" {
		// Announce our endpoint to etcd if so configured.
		unannounceHTTP := serverutil.AnnounceSelf(ctx, client, *etcdHTTPService, *httpEndpoint)
		defer unannounceHTTP()
	}

	// Start the sequencing loop, which will run until we terminate the process. This controls
	// both sequencing and signing.
	// TODO(Martin2112): Should respect read only mode and the flags in tree control etc
	log.QuotaIncreaseFactor = *quotaIncreaseFactor
	sequencerManager := log.NewSequencerManager(registry, *sequencerGuardWindowFlag)
	info := log.OperationInfo{
		Registry:    registry,
		BatchSize:   *batchSizeFlag,
		NumWorkers:  *numSeqFlag,
		RunInterval: *sequencerIntervalFlag,
		TimeSource:  clock.System,
		ElectionConfig: election.RunnerConfig{
			PreElectionPause:   *preElectionPause,
			MasterHoldInterval: *masterHoldInterval,
			MasterHoldJitter:   *masterHoldJitter,
			TimeSource:         clock.System,
		},
	}
	sequencerTask := log.NewOperationManager(info, sequencerManager)

	go sequencerTask.OperationLoop(ctx)

	m := serverutil.Main{
		RPCEndpoint:      *rpcEndpoint,
		HTTPEndpoint:     *httpEndpoint,
		TLSCertFile:      *tlsCertFile,
		TLSKeyFile:       *tlsKeyFile,
		StatsPrefix:      "logsigner",
		DBClose:          sp.Close,
		Registry:         registry,
		RegisterServerFn: func(s *grpc.Server, _ extension.Registry) error { return nil },
		IsHealthy:        sp.AdminStorage().CheckDatabaseAccessible,
		HealthyDeadline:  *healthzTimeout,
	}

	if err := m.Run(ctx); err != nil {
		logger.Fatalf("Server exited with error: %v", err)
	}

	// Give things a few seconds to tidy up
	logger.Infof("Stopping server, about to exit")
	time.Sleep(time.Second * 5) // nolint: gomnd
}
