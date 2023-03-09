/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/ceda464a95a36e37e16fb361a5e426877c49d450/cmd/
trillian_log_signer/main.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// The log_signer binary runs the log signing code.
package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/google/trillian/log"
	"github.com/google/trillian/quota"
	"github.com/google/trillian/storage"
	logs "github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vct/cmd/log_signer/startcmd"
	"github.com/trustbloc/vct/pkg/storage/memory"
	"github.com/trustbloc/vct/pkg/storage/postgres"
)

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
	pgConnStr  = flag.String("pg_conn_str", "user=postgres dbname=test sslmode=disable", "Connection string for Postgres database")
)

var logger = logs.New("log-signer")

func main() {
	flag.Parse()

	if err := storage.RegisterProvider("mem", memory.NewMemoryStorageProvider); err != nil {
		logger.Error("Error registering memory storage provider", logs.WithError(err))
	}

	postgres.PGConnStr = *pgConnStr

	if err := storage.RegisterProvider("postgres", postgres.NewPGProvider); err != nil {
		logger.Error("Error registering PostGreSQL storage provider", logs.WithError(err))
	}

	startCMD := startcmd.CMD{
		RPCEndpoint:              *rpcEndpoint,
		HTTPEndpoint:             *httpEndpoint,
		HealthzTimeout:           *healthzTimeout,
		TLSCertFile:              *tlsCertFile,
		TLSKeyFile:               *tlsKeyFile,
		SequencerIntervalFlag:    *sequencerIntervalFlag,
		ETCDHTTPService:          *etcdHTTPService,
		QuotaSystem:              *quotaSystem,
		BatchSizeFlag:            *batchSizeFlag,
		StorageSystem:            *storageSystem,
		NumSeqFlag:               *numSeqFlag,
		SequencerGuardWindowFlag: *sequencerGuardWindowFlag,
		LockDir:                  *lockDir,
		ForceMaster:              *forceMaster,
		PREElectionPause:         *preElectionPause,
		QuotaIncreaseFactor:      *quotaIncreaseFactor,
		ConfigFile:               *configFile,
		PGConnStr:                *pgConnStr,
		MasterHoldInterval:       *masterHoldInterval,
		MasterHoldJitter:         *masterHoldJitter,
	}

	if err := startCMD.Start(); err != nil {
		logger.Fatal("failed to start log signer", logs.WithError(err))
	}
}
