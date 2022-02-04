/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/ceda464a95a36e37e16fb361a5e426877c49d450/cmd/trillian_log_server/main.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// The log_server binary runs the Trillian log server, and also
// provides an admin server.
package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/google/trillian/quota"
	"github.com/google/trillian/storage"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/vct/cmd/internal/serverutil"
	"github.com/trustbloc/vct/cmd/log_server/startcmd"
	"github.com/trustbloc/vct/pkg/storage/memory"
	"github.com/trustbloc/vct/pkg/storage/postgres"
)

const defaultHealthzTimeout = time.Second * 5

// nolint: lll
var (
	rpcEndpoint     = flag.String("rpc_endpoint", "localhost:8090", "Endpoint for RPC requests (host:port)")
	httpEndpoint    = flag.String("http_endpoint", "localhost:8091", "Endpoint for HTTP metrics (host:port, empty means disabled)")
	healthzTimeout  = flag.Duration("healthz_timeout", defaultHealthzTimeout, "Timeout used during healthz checks")
	tlsCertFile     = flag.String("tls_cert_file", "", "Path to the TLS server certificate. If unset, the server will use unsecured connections.")
	tlsKeyFile      = flag.String("tls_key_file", "", "Path to the TLS server key. If unset, the server will use unsecured connections.")
	etcdService     = flag.String("etcd_service", "trillian-logserver", "Service name to announce ourselves under")
	etcdHTTPService = flag.String("etcd_http_service", "trillian-logserver-http", "Service name to announce our HTTP endpoint under")

	quotaSystem = flag.String("quota_system", "mysql", fmt.Sprintf("Quota system to use. One of: %v", quota.Providers()))
	quotaDryRun = flag.Bool("quota_dry_run", false, "If true no requests are blocked due to lack of tokens")

	storageSystem = flag.String("storage_system", "mysql", fmt.Sprintf("Storage system to use. One of: %v", storage.Providers()))

	treeGCEnabled            = flag.Bool("tree_gc", true, "If true, tree garbage collection (hard-deletion) is periodically performed")
	treeDeleteThreshold      = flag.Duration("tree_delete_threshold", serverutil.DefaultTreeDeleteThreshold, "Minimum period a tree has to remain deleted before being hard-deleted")
	treeDeleteMinRunInterval = flag.Duration("tree_delete_min_run_interval", serverutil.DefaultTreeDeleteMinInterval, "Minimum interval between tree garbage collection sweeps. Actual runs happen randomly between [minInterval,2*minInterval).")

	tracing          = flag.Bool("tracing", false, "If true opencensus Stackdriver tracing will be enabled. See https://opencensus.io/.")
	tracingProjectID = flag.String("tracing_project_id", "", "project ID to pass to stackdriver. Can be empty for GCP, consult docs for other platforms.")
	tracingPercent   = flag.Int("tracing_percent", 0, "Percent of requests to be traced. Zero is a special case to use the DefaultSampler")

	configFile = flag.String("config", "", "Config file containing flags, file contents can be overridden by command line flags")
	pgConnStr  = flag.String("pg_conn_str", "user=postgres dbname=test sslmode=disable", "Connection string for Postgres database")
)

var logger = log.New("log-server")

func main() {
	flag.Parse()

	if err := storage.RegisterProvider("mem", memory.NewMemoryStorageProvider); err != nil {
		logger.Errorf(err.Error())
	}

	postgres.PGConnStr = *pgConnStr

	if err := storage.RegisterProvider("postgres", postgres.NewPGProvider); err != nil {
		logger.Errorf(err.Error())
	}

	startCMD := startcmd.CMD{
		RPCEndpoint:              *rpcEndpoint,
		HTTPEndpoint:             *httpEndpoint,
		HealthzTimeout:           *healthzTimeout,
		TLSCertFile:              *tlsCertFile,
		TLSKeyFile:               *tlsKeyFile,
		ETCDService:              *etcdService,
		ETCDHTTPService:          *etcdHTTPService,
		QuotaSystem:              *quotaSystem,
		QuotaDryRun:              *quotaDryRun,
		StorageSystem:            *storageSystem,
		TreeGCEnabled:            *treeGCEnabled,
		TreeDeleteThreshold:      *treeDeleteThreshold,
		TreeDeleteMinRunInterval: *treeDeleteMinRunInterval,
		Tracing:                  *tracing,
		TracingProjectID:         *tracingProjectID,
		TracingPercent:           *tracingPercent,
		ConfigFile:               *configFile,
		PGConnStr:                *pgConnStr,
	}

	if err := startCMD.Start(); err != nil {
		logger.Fatalf("failed to start log server: %v", err)
	}
}
