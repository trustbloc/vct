/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/ceda464a95a36e37e16fb361a5e426877c49d450/cmd/trillian_log_server/main.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package startcmd runs the Trillian log server, and also
// provides an admin server.
package startcmd

import (
	"context"
	"fmt"
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
	"github.com/google/trillian/server"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/util/clock"
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
	ETCDService              string
	ETCDHTTPService          string
	QuotaSystem              string
	QuotaDryRun              bool
	StorageSystem            string
	TreeGCEnabled            bool
	TreeDeleteThreshold      time.Duration
	TreeDeleteMinRunInterval time.Duration
	Tracing                  bool
	TracingProjectID         string
	TracingPercent           int
	ConfigFile               string
	PGConnStr                string
}

// Start server.
func (s *CMD) Start() error { //nolint: funlen
	if s.ConfigFile != "" {
		if err := cmd.ParseFlagFile(s.ConfigFile); err != nil {
			return fmt.Errorf("failed to load flags from config file %q: %w", s.ConfigFile, err)
		}
	}

	ctx := context.Background()

	var options []grpc.ServerOption

	mf := prometheus.MetricFactory{}

	monitoring.SetStartSpan(opencensus.StartSpan)

	if s.Tracing {
		opts, err := opencensus.EnableRPCServerTracing(s.TracingProjectID, s.TracingPercent)
		if err != nil {
			return fmt.Errorf("failed to initialize stackdriver / opencensus tracing: %w", err)
		}
		// Enable the server request counter tracing etc.
		options = append(options, opts...)
	}

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

	// Announce our endpoints to etcd if so configured.
	unannounce := serverutil.AnnounceSelf(ctx, client, s.ETCDService, s.RPCEndpoint)
	defer unannounce()

	if s.HTTPEndpoint != "" {
		unannounceHTTP := serverutil.AnnounceSelf(ctx, client, s.ETCDHTTPService, s.HTTPEndpoint)
		defer unannounceHTTP()
	}

	qm, err := quota.NewManager(s.QuotaSystem)
	if err != nil {
		return fmt.Errorf("error creating quota manager: %w", err)
	}

	registry := extension.Registry{
		AdminStorage:  sp.AdminStorage(),
		LogStorage:    sp.LogStorage(),
		QuotaManager:  qm,
		MetricFactory: mf,
	}

	m := serverutil.Main{
		RPCEndpoint:  s.RPCEndpoint,
		HTTPEndpoint: s.HTTPEndpoint,
		TLSCertFile:  s.TLSCertFile,
		TLSKeyFile:   s.TLSKeyFile,
		StatsPrefix:  "log",
		ExtraOptions: options,
		QuotaDryRun:  s.QuotaDryRun,
		DBClose:      sp.Close,
		Registry:     registry,
		RegisterServerFn: func(grpc *grpc.Server, registry extension.Registry) error {
			logServer := server.NewTrillianLogRPCServer(registry, clock.System)
			if err := logServer.IsHealthy(); err != nil {
				return err
			}
			trillian.RegisterTrillianLogServer(grpc, logServer)
			if s.QuotaSystem == etcd.QuotaManagerName {
				quotapb.RegisterQuotaServer(grpc, quotaapi.NewServer(client))
			}

			return nil
		},
		IsHealthy: func(ctx context.Context) error {
			as := sp.AdminStorage()

			return as.CheckDatabaseAccessible(ctx)
		},
		HealthyDeadline:       s.HealthzTimeout,
		AllowedTreeTypes:      []trillian.TreeType{trillian.TreeType_LOG, trillian.TreeType_PREORDERED_LOG},
		TreeGCEnabled:         s.TreeGCEnabled,
		TreeDeleteThreshold:   s.TreeDeleteThreshold,
		TreeDeleteMinInterval: s.TreeDeleteMinRunInterval,
	}

	if err := m.Run(ctx); err != nil {
		return fmt.Errorf("server exited with error: %w", err)
	}

	return nil
}
