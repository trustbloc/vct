/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/ceda464a95a36e37e16fb361a5e426877c49d450/cmd/internal/serverutil/main.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package serverutil holds code for running Trillian servers.
package serverutil

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/extension"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/server/admin"
	"github.com/google/trillian/server/interceptor"
	"github.com/google/trillian/util"
	"github.com/google/trillian/util/clock"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/naming/endpoints"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var logger = log.New("internal/serverutil")

const (
	// DefaultTreeDeleteThreshold is the suggested threshold for tree deletion.
	// It represents the minimum time a tree has to remain Deleted before being hard-deleted.
	DefaultTreeDeleteThreshold = 7 * 24 * time.Hour

	// DefaultTreeDeleteMinInterval is the suggested min interval between tree GC sweeps.
	// A tree GC sweep consists of listing deleted trees older than the deletion threshold and
	// hard-deleting them.
	// Actual runs happen randomly between [minInterval,2*minInterval).
	DefaultTreeDeleteMinInterval = 4 * time.Hour
)

// Main encapsulates the data and logic to start a Trillian server (Log or Map).
type Main struct {
	// Endpoints for RPC and HTTP servers.
	// HTTP is optional, if empty it'll not be bound.
	RPCEndpoint, HTTPEndpoint string

	// TLS Certificate and Key files for the server.
	TLSCertFile, TLSKeyFile string

	DBClose func() error

	Registry extension.Registry

	StatsPrefix string
	QuotaDryRun bool

	// RegisterServerFn is called to register RPC servers.
	RegisterServerFn func(*grpc.Server, extension.Registry) error

	// IsHealthy will be called whenever "/healthz" is called on the mux.
	// A nil return value from this function will result in a 200-OK response
	// on the /healthz endpoint.
	IsHealthy func(context.Context) error
	// HealthyDeadline is the maximum duration to wait wait for a successful
	// IsHealthy() call.
	HealthyDeadline time.Duration

	// AllowedTreeTypes determines which types of trees may be created through the Admin Server
	// bound by Main. nil means unrestricted.
	AllowedTreeTypes []trillian.TreeType

	TreeGCEnabled         bool
	TreeDeleteThreshold   time.Duration
	TreeDeleteMinInterval time.Duration

	// These will be added to the GRPC server options.
	ExtraOptions []grpc.ServerOption
}

func (m *Main) healthz(rw http.ResponseWriter, req *http.Request) {
	if m.IsHealthy != nil {
		ctx, cancel := context.WithTimeout(req.Context(), m.HealthyDeadline)
		defer cancel()

		if err := m.IsHealthy(ctx); err != nil {
			rw.WriteHeader(http.StatusServiceUnavailable)
			rw.Write([]byte(err.Error())) // nolint: errcheck, gosec

			return
		}
	}

	rw.Write([]byte("ok")) // nolint: errcheck, gosec
}

// Run starts the configured server. Blocks until the server exits.
func (m *Main) Run(ctx context.Context) error { // nolint: funlen
	const defaultHealthyDeadline = 5 * time.Second

	if m.HealthyDeadline == 0 {
		m.HealthyDeadline = defaultHealthyDeadline
	}

	srv, err := m.newGRPCServer()
	if err != nil {
		logger.Fatalf("Error creating gRPC server: %v", err)
	}

	defer srv.GracefulStop()

	defer m.DBClose() // nolint: errcheck

	err = m.RegisterServerFn(srv, m.Registry)
	if err != nil {
		return err
	}

	trillian.RegisterTrillianAdminServer(srv, admin.New(m.Registry, m.AllowedTreeTypes))
	reflection.Register(srv)

	if endpoint := m.HTTPEndpoint; endpoint != "" {
		http.Handle("/metrics", promhttp.Handler())
		http.HandleFunc("/healthz", m.healthz)

		go func() {
			logger.Infof("HTTP server starting on %v", endpoint)

			// Let http.ListenAndServeTLS handle the error case when only one of the flags is set.
			if m.TLSCertFile != "" || m.TLSKeyFile != "" {
				err = http.ListenAndServeTLS(endpoint, m.TLSCertFile, m.TLSKeyFile, nil)
			} else {
				err = http.ListenAndServe(endpoint, nil)
			}

			if err != nil {
				logger.Errorf("HTTP server stopped: %v", err)
			}
		}()
	}

	logger.Infof("RPC server starting on %v", m.RPCEndpoint)

	lis, err := net.Listen("tcp", m.RPCEndpoint)
	if err != nil {
		return err
	}

	go util.AwaitSignal(ctx, srv.Stop)

	if m.TreeGCEnabled {
		go func() {
			logger.Infof("Deleted tree GC started")

			gc := admin.NewDeletedTreeGC(
				m.Registry.AdminStorage,
				m.TreeDeleteThreshold,
				m.TreeDeleteMinInterval,
				m.Registry.MetricFactory)
			gc.Run(ctx)
		}()
	}

	if err := srv.Serve(lis); err != nil {
		logger.Errorf("RPC server terminated: %v", err)
	}

	logger.Infof("Stopping server, about to exit")

	// Give things a few seconds to tidy up
	time.Sleep(time.Second * 5) // nolint: gomnd

	return nil
}

// newGRPCServer starts a new Trillian gRPC server.
func (m *Main) newGRPCServer() (*grpc.Server, error) {
	stats := monitoring.NewRPCStatsInterceptor(clock.System, m.StatsPrefix, m.Registry.MetricFactory)
	ti := interceptor.New(m.Registry.AdminStorage, m.Registry.QuotaManager, m.QuotaDryRun, m.Registry.MetricFactory)

	serverOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			stats.Interceptor(),
			interceptor.ErrorWrapper,
			ti.UnaryInterceptor,
		)),
	}
	serverOpts = append(serverOpts, m.ExtraOptions...)

	// Let credentials.NewServerTLSFromFile handle the error case when only one of the flags is set.
	if m.TLSCertFile != "" || m.TLSKeyFile != "" {
		serverCreds, err := credentials.NewServerTLSFromFile(m.TLSCertFile, m.TLSKeyFile)
		if err != nil {
			return nil, err
		}

		serverOpts = append(serverOpts, grpc.Creds(serverCreds))
	}

	s := grpc.NewServer(serverOpts...)

	return s, nil
}

// AnnounceSelf announces this binary's presence to etcd.  Returns a function that
// should be called on process exit.
// AnnounceSelf does nothing if client is nil.
func AnnounceSelf(ctx context.Context, client *clientv3.Client, etcdService, endpoint string) func() {
	if client == nil {
		return func() {}
	}

	// Get a lease so our entry self-destructs.
	leaseRsp, err := client.Grant(ctx, 30)
	if err != nil {
		logger.Fatalf("Failed to get lease from etcd: %v", err)
	}

	client.KeepAlive(ctx, leaseRsp.ID) // nolint: errcheck, gosec

	em, err := endpoints.NewManager(client, etcdService)
	if err != nil {
		logger.Fatalf("Failed to create etcd manager: %v", err)
	}

	fullEndpoint := fmt.Sprintf("%s/%s", etcdService, endpoint)
	em.AddEndpoint(ctx, fullEndpoint, endpoints.Endpoint{Addr: endpoint}) // nolint: errcheck, gosec
	logger.Infof("Announcing our presence in %v", etcdService)

	return func() {
		// Use a background context because the original context may have been cancelled.
		logger.Infof("Removing our presence in %v", etcdService)

		ctx := context.Background()
		em.DeleteEndpoint(ctx, fullEndpoint) // nolint: errcheck, gosec
		client.Revoke(ctx, leaseRsp.ID)      // nolint: errcheck, gosec
	}
}

const (
	importConnStrFlag = "import_conn_str"
	storageSystemFlag = "storage_system"
	pgConnStrFlag     = "pg_conn_str"
	mysqlURIFlag      = "mysql_uri"
)

// ImportPostgres imports schema.
func ImportPostgres(query string) error {
	var (
		connStr       = flag.Lookup(importConnStrFlag).Value.String()
		storageSystem = flag.Lookup(storageSystemFlag).Value.String()
	)

	if strings.TrimSpace(connStr) == "" {
		connStr = flag.Lookup(pgConnStrFlag).Value.String()
	}

	db, err := sql.Open(storageSystem, connStr)
	if err != nil {
		return fmt.Errorf("error opening %s: %w", storageSystem, err)
	}

	defer db.Close() // nolint: errcheck

	_, err = db.Exec(query)
	// When starting with multiple instances, these errors are possible. They're benign - they just mean another
	// server won the race and got the table set up first.
	if err != nil && (strings.Contains(err.Error(), "already exists") ||
		strings.Contains(err.Error(), "duplicate key value violates unique constraint")) {
		return nil
	}

	return err
}

// ImportMySQL imports schema.
func ImportMySQL(queries ...string) error {
	var (
		connStr       = flag.Lookup("import_conn_str").Value.String()
		storageSystem = flag.Lookup(storageSystemFlag).Value.String()
	)

	if strings.TrimSpace(connStr) == "" {
		connStr = flag.Lookup(mysqlURIFlag).Value.String()
	}

	db, err := sql.Open(storageSystem, connStr)
	if err != nil {
		return fmt.Errorf("error opening %s: %w", storageSystem, err)
	}

	defer db.Close() // nolint: errcheck

	tx, err := db.Begin()
	if err != nil {
		logger.Fatalf("Failed to begin %s transaction: %v", storageSystem, err)
	}

	defer func() { tx.Rollback() }() // nolint: errcheck,gosec

	for _, query := range queries {
		query = strings.TrimSpace(query)
		if query == "" {
			continue
		}

		_, err = tx.Exec(query)
		if err != nil && !strings.Contains(err.Error(), "Duplicate key name") {
			logger.Fatalf("Error importing %s schema: %v", storageSystem, err)
		}
	}

	return tx.Commit()
}
