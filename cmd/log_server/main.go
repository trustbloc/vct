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
	"context"
	"flag"
	"fmt"

	// nolint:gosec
	_ "net/http/pprof"
	"strings"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/cmd"
	"github.com/google/trillian/extension"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/opencensus"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/google/trillian/quota"
	"github.com/google/trillian/quota/etcd"
	"github.com/google/trillian/quota/etcd/quotaapi"
	"github.com/google/trillian/quota/etcd/quotapb"
	_ "github.com/google/trillian/quota/mysqlqm"
	"github.com/google/trillian/server"
	"github.com/google/trillian/storage"
	_ "github.com/google/trillian/storage/cloudspanner"
	_ "github.com/google/trillian/storage/mysql"
	"github.com/google/trillian/util/clock"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"

	"github.com/trustbloc/vct/cmd/internal/serverutil"
	_ "github.com/trustbloc/vct/pkg/storage/postgres"
)

var logger = log.New("log-server")

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
)

func main() { // nolint: funlen
	flag.Parse()

	if *configFile != "" {
		if err := cmd.ParseFlagFile(*configFile); err != nil {
			logger.Fatalf("Failed to load flags from config file %q: %s", *configFile, err)
		}
	}

	ctx := context.Background()

	var options []grpc.ServerOption

	mf := prometheus.MetricFactory{}

	monitoring.SetStartSpan(opencensus.StartSpan)

	if *tracing {
		opts, err := opencensus.EnableRPCServerTracing(*tracingProjectID, *tracingPercent)
		if err != nil {
			logger.Fatalf("Failed to initialize stackdriver / opencensus tracing: %v", err)
		}
		// Enable the server request counter tracing etc.
		options = append(options, opts...)
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

	// Announce our endpoints to etcd if so configured.
	unannounce := serverutil.AnnounceSelf(ctx, client, *etcdService, *rpcEndpoint)
	defer unannounce()

	if *httpEndpoint != "" {
		unannounceHTTP := serverutil.AnnounceSelf(ctx, client, *etcdHTTPService, *httpEndpoint)
		defer unannounceHTTP()
	}

	qm, err := quota.NewManager(*quotaSystem)
	if err != nil {
		logger.Fatalf("Error creating quota manager: %v", err)
	}

	registry := extension.Registry{
		AdminStorage:  sp.AdminStorage(),
		LogStorage:    sp.LogStorage(),
		QuotaManager:  qm,
		MetricFactory: mf,
	}

	m := serverutil.Main{
		RPCEndpoint:  *rpcEndpoint,
		HTTPEndpoint: *httpEndpoint,
		TLSCertFile:  *tlsCertFile,
		TLSKeyFile:   *tlsKeyFile,
		StatsPrefix:  "log",
		ExtraOptions: options,
		QuotaDryRun:  *quotaDryRun,
		DBClose:      sp.Close,
		Registry:     registry,
		RegisterServerFn: func(s *grpc.Server, registry extension.Registry) error {
			logServer := server.NewTrillianLogRPCServer(registry, clock.System)
			if err := logServer.IsHealthy(); err != nil {
				return err
			}
			trillian.RegisterTrillianLogServer(s, logServer)
			if *quotaSystem == etcd.QuotaManagerName {
				quotapb.RegisterQuotaServer(s, quotaapi.NewServer(client))
			}

			return nil
		},
		IsHealthy: func(ctx context.Context) error {
			as := sp.AdminStorage()

			return as.CheckDatabaseAccessible(ctx)
		},
		HealthyDeadline:       *healthzTimeout,
		AllowedTreeTypes:      []trillian.TreeType{trillian.TreeType_LOG, trillian.TreeType_PREORDERED_LOG},
		TreeGCEnabled:         *treeGCEnabled,
		TreeDeleteThreshold:   *treeDeleteThreshold,
		TreeDeleteMinInterval: *treeDeleteMinRunInterval,
	}

	if err := m.Run(ctx); err != nil {
		logger.Fatalf("Server exited with error: %v", err)
	}
}
