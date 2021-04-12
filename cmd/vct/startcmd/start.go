/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/spf13/cobra"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/rest"
)

const (
	envPrefix = "VCT_"

	agentHostFlagName      = "api-host"
	agentHostEnvKey        = envPrefix + "API_HOST"
	agentHostFlagShorthand = "a"
	agentHostFlagUsage     = "Host Name:Port." +
		" Alternatively, this can be set with the following environment variable: " + agentHostEnvKey

	logIDFlagName      = "log-id"
	logIDEnvKey        = envPrefix + "LOG_ID"
	logIDFlagShorthand = "l"
	logIDFlagUsage     = "Trillian log id." +
		" Alternatively, this can be set with the following environment variable: " + logIDEnvKey

	logEndpointFlagName      = "log-endpoint"
	logEndpointEnvKey        = envPrefix + "LOG_ENDPOINT"
	logEndpointFlagShorthand = "e"
	logEndpointFlagUsage     = "Trillian log id." +
		" Alternatively, this can be set with the following environment variable: " + logEndpointEnvKey

	kmsStoreEndpointFlagName      = "kms-store-endpoint"
	kmsStoreEndpointEnvKey        = envPrefix + "KMS_STORE_ENDPOINT"
	kmsStoreEndpointFlagShorthand = "k"
	kmsStoreEndpointFlagUsage     = "Remote KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsStoreEndpointEnvKey

	keyIDFlagName      = "key-id"
	keyIDEnvKey        = envPrefix + "KEY_ID"
	keyIDFlagShorthand = "i"
	keyIDFlagUsage     = "Key ID." +
		" Alternatively, this can be set with the following environment variable: " + keyIDEnvKey

	keyTypeFlagName      = "key-type"
	keyTypeEnvKey        = envPrefix + "KEY_TYPE"
	keyTypeFlagShorthand = "t"
	keyTypeFlagUsage     = "Key type." +
		" Alternatively, this can be set with the following environment variable: " + keyTypeEnvKey

	datasourceNameFlagName      = "dsn"
	datasourceNameFlagShorthand = "d"
	datasourceNameFlagUsage     = "Datasource Name with credentials if required." +
		" Format must be <driver>:[//]<driver-specific-dsn>." +
		" Examples: 'mysql://root:secret@tcp(localhost:3306)/adapter', 'mem://test'." +
		" Supported drivers are [mem, couchdb, mysql]." +
		" Alternatively, this can be set with the following environment variable: " + datasourceNameEnvKey
	datasourceNameEnvKey = envPrefix + "DSN"

	datasourceTimeoutFlagName  = "dsn-timeout"
	datasourceTimeoutFlagUsage = "Total time in seconds to wait until the datasource is available before giving up." +
		" Default: 30 seconds." +
		" Alternatively, this can be set with the following environment variable: " + datasourceTimeoutEnvKey
	datasourceTimeoutEnvKey = envPrefix + "DSN_TIMEOUT"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = envPrefix + "TLS_SYSTEMCERTPOOL"

	testTreeFlagName  = "test-tree"
	testTreeFlagUsage = "Creates test tree." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + testTreeEnvKey
	testTreeEnvKey = envPrefix + "TEST_TREE"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = envPrefix + "TLS_CACERTS"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = envPrefix + "TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = envPrefix + "TLS_SERVE_KEY"
)

const (
	databaseTypeMemOption     = "mem"
	databaseTypeMySQLOption   = "mysql"
	databaseTypeCouchDBOption = "couchdb"
)

var logger = log.New("vct/startcmd")

// nolint:gochecknoglobals
var supportedStorageProviders = map[string]func(string, string) (storage.Provider, error){
	databaseTypeCouchDBOption: func(dsn, prefix string) (storage.Provider, error) {
		return couchdb.NewProvider(dsn, couchdb.WithDBPrefix(prefix)) // nolint: wrapcheck
	},
	databaseTypeMySQLOption: func(dsn, prefix string) (storage.Provider, error) {
		return mysql.NewProvider(dsn, mysql.WithDBPrefix(prefix)) // nolint: wrapcheck
	},
	databaseTypeMemOption: func(_, _ string) (storage.Provider, error) { // nolint: unparam
		return mem.NewProvider(), nil
	},
}

type server interface {
	ListenAndServe(host string, router http.Handler, certFile, keyFile string) error
}

// HTTPServer represents an actual server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler, certFile, keyFile string) error {
	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(host, certFile, keyFile, router) // nolint: wrapcheck
	}

	return http.ListenAndServe(host, router) // nolint: wrapcheck
}

// Cmd returns the Cobra start command.
func Cmd(server server) (*cobra.Command, error) {
	startCmd := createStartCMD(server)

	createFlags(startCmd)

	return startCmd, nil
}

type agentParameters struct {
	logID             int64
	testTree          bool
	host              string
	logEndpoint       string
	keyID             string
	keyType           kms.KeyType
	datasourceName    string
	datasourceTimeout uint64
	datasourcePrefix  string
	kmsStoreEndpoint  string
	tlsParams         *tlsParameters
	server            server
}

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

func createStartCMD(server server) *cobra.Command { // nolint: funlen
	return &cobra.Command{
		Use:   "start",
		Short: "Starts vct service",
		Long:  `Starts verifiable credentials transparency service`,
		RunE: func(cmd *cobra.Command, args []string) error {
			host, err := getUserSetVar(cmd, agentHostFlagName, agentHostEnvKey, false)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", agentHostFlagName, agentHostEnvKey, err)
			}

			testTreeStr := getUserSetVarOptional(cmd, testTreeFlagName, testTreeEnvKey)
			testTree, err := strconv.ParseBool(testTreeStr)
			if err != nil {
				return fmt.Errorf("parse test tree: %w", err)
			}

			if testTree {
				logger.Warnf("VCT is running in test mode. Do not use %q option for production!", testTreeFlagName)
			}

			logIDVal, err := getUserSetVar(cmd, logIDFlagName, logIDEnvKey, testTree)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", logIDFlagName, logIDEnvKey, err)
			}

			logID, err := strconv.ParseInt(logIDVal, 10, 64)
			if !testTree && err != nil {
				return fmt.Errorf("log ID is not a number: %w", err)
			}

			logEndpoint, err := getUserSetVar(cmd, logEndpointFlagName, logEndpointEnvKey, false)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", logEndpointFlagName, logEndpointEnvKey, err)
			}

			keyID := getUserSetVarOptional(cmd, keyIDFlagName, keyIDEnvKey)
			keyType := getUserSetVarOptional(cmd, keyTypeFlagName, keyTypeEnvKey)
			kmsStoreEndpoint := getUserSetVarOptional(cmd, kmsStoreEndpointFlagName, kmsStoreEndpointEnvKey)
			datasourceName := getUserSetVarOptional(cmd, datasourceNameFlagName, datasourceNameEnvKey)
			datasourceTimeoutStr := getUserSetVarOptional(cmd, datasourceTimeoutFlagName, datasourceTimeoutEnvKey)

			datasourceTimeout, err := strconv.ParseUint(datasourceTimeoutStr, 10, 64)
			if err != nil {
				return fmt.Errorf("timeout is not a number(positive): %w", err)
			}

			tlsParams, err := getTLS(cmd)
			if err != nil {
				return fmt.Errorf("get TLS (%s or %s): %w", keyTypeFlagName, keyTypeEnvKey, err)
			}

			parameters := &agentParameters{
				server:            server,
				testTree:          testTree,
				host:              host,
				logID:             logID,
				logEndpoint:       logEndpoint,
				kmsStoreEndpoint:  kmsStoreEndpoint,
				keyID:             keyID,
				keyType:           kms.KeyType(keyType),
				datasourceName:    datasourceName,
				tlsParams:         tlsParams,
				datasourceTimeout: datasourceTimeout,
			}

			return startAgent(parameters)
		},
	}
}

func getUserSetVarOptional(cmd *cobra.Command, flagName, envKey string) string {
	// no need to check errors for optional flags
	val, _ := getUserSetVar(cmd, flagName, envKey, true) // nolint: errcheck

	return val
}

const defaultMasterKeyURI = "local-lock://default/master/key/"

func createKMSAndCrypto(parameters *agentParameters, client *http.Client,
	store storage.Provider) (kms.KeyManager, crypto.Crypto, error) {
	endpoint := parameters.kmsStoreEndpoint

	if endpoint != "" {
		return webkms.New(endpoint, client), webcrypto.New(endpoint, client), nil
	}

	local, err := localkms.New(defaultMasterKeyURI, &kmsProvider{
		storageProvider: store,
		secretLock:      &noop.NoLock{},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create kms: %w", err)
	}

	cr, err := tinkcrypto.New()
	if err != nil {
		return nil, nil, fmt.Errorf("create crypto: %w", err)
	}

	return local, cr, nil
}

func createKID(km kms.KeyManager, parameters *agentParameters) error {
	var err error

	parameters.keyID, _, err = km.Create(parameters.keyType)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}

	logger.Infof("Key id %s was created and will be used in a service", parameters.keyID)

	return nil
}

func startAgent(parameters *agentParameters) error { // nolint: funlen
	store, err := createStoreProvider(
		parameters.datasourceName,
		parameters.datasourceTimeout,
		parameters.datasourcePrefix,
	)
	if err != nil {
		return fmt.Errorf("create store provider: %w", err)
	}

	defer func() {
		if err = store.Close(); err != nil {
			logger.Errorf("store close: %v", err)
		}
	}()

	rootCAs, err := tlsutils.GetCertPool(parameters.tlsParams.systemCertPool, parameters.tlsParams.caCerts)
	if err != nil {
		return fmt.Errorf("get cert pool: %w", err)
	}

	km, cr, err := createKMSAndCrypto(parameters, &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
		},
	}, store)
	if err != nil {
		return fmt.Errorf("create kms and crypto: %w", err)
	}

	if parameters.keyID == "" {
		if err = createKID(km, parameters); err != nil {
			return fmt.Errorf("create kid: %w", err)
		}
	}

	conn, err := grpc.Dial(parameters.logEndpoint, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("grpc dial: %w", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			logger.Errorf("connection close: %v", err)
		}
	}()

	if parameters.testTree {
		var tree *trillian.Tree

		tree, err = createTree(conn)
		if err != nil {
			return fmt.Errorf("create tree: %w", err)
		}

		parameters.logID = tree.TreeId
	}

	cmd, err := command.New(&command.Config{
		Trillian: trillian.NewTrillianLogClient(conn),
		KMS:      km,
		Crypto:   cr,
		VDR:      vdr.New(&kmsCtx{KeyManager: km}, vdr.WithVDR(vdrkey.New())),
		LogID:    parameters.logID,
		Key: command.Key{
			ID:   parameters.keyID,
			Type: parameters.keyType,
		},
		Issuers: []string{},
	})
	if err != nil {
		return fmt.Errorf("create command instance: %w", err)
	}

	router := mux.NewRouter()

	for _, handler := range rest.New(cmd).GetRESTHandlers() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting vct on host [%s]", parameters.host)

	return parameters.server.ListenAndServe( // nolint: wrapcheck
		parameters.host,
		router,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
	)
}

func createTree(conn *grpc.ClientConn) (*trillian.Tree, error) {
	// nolint: wrapcheck
	return trillian.NewTrillianAdminClient(conn).CreateTree(context.Background(), &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeState:          trillian.TreeState_ACTIVE,
			TreeType:           trillian.TreeType_LOG,
			HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
			HashAlgorithm:      sigpb.DigitallySigned_SHA256,
			SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
			MaxRootDuration:    durationpb.New(time.Hour),
		},
		KeySpec: &keyspb.Specification{
			Params: &keyspb.Specification_EcdsaParams{
				EcdsaParams: &keyspb.Specification_ECDSA{},
			},
		},
	})
}

func getUserSetVar(cmd *cobra.Command, flagName, envKey string, isOptional bool) (string, error) {
	defaultOrFlagVal, err := cmd.Flags().GetString(flagName)
	if cmd.Flags().Changed(flagName) {
		return defaultOrFlagVal, err // nolint: wrapcheck
	}

	value, isSet := os.LookupEnv(envKey)
	if isSet {
		return value, nil
	}

	if isOptional || defaultOrFlagVal != "" {
		return defaultOrFlagVal, nil
	}

	return "", fmt.Errorf("neither %s (command line flag) nor %s (environment variable) have been set",
		flagName, envKey)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(agentHostFlagName, agentHostFlagShorthand, "", agentHostFlagUsage)
	startCmd.Flags().StringP(logIDFlagName, logIDFlagShorthand, "", logIDFlagUsage)
	startCmd.Flags().StringP(logEndpointFlagName, logEndpointFlagShorthand, "", logEndpointFlagUsage)
	startCmd.Flags().StringP(kmsStoreEndpointFlagName, kmsStoreEndpointFlagShorthand, "", kmsStoreEndpointFlagUsage)
	startCmd.Flags().StringP(keyIDFlagName, keyIDFlagShorthand, "", keyIDFlagUsage)
	startCmd.Flags().StringP(keyTypeFlagName, keyTypeFlagShorthand, string(kms.ECDSAP256TypeIEEEP1363), keyTypeFlagUsage)
	startCmd.Flags().StringP(datasourceNameFlagName, datasourceNameFlagShorthand, "mem://test", datasourceNameFlagUsage)
	startCmd.Flags().String(datasourceTimeoutFlagName, "30", datasourceTimeoutFlagUsage)
	startCmd.Flags().String(tlsSystemCertPoolFlagName, "false", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().String(tlsCACertsFlagName, "", tlsCACertsFlagUsage)
	startCmd.Flags().String(tlsServeCertPathFlagName, "", tlsServeCertPathFlagUsage)
	startCmd.Flags().String(tlsServeKeyPathFlagName, "", tlsServeKeyPathFlagUsage)
	startCmd.Flags().String(testTreeFlagName, "false", testTreeFlagUsage)
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPoolString := getUserSetVarOptional(cmd, tlsSystemCertPoolFlagName, tlsSystemCertPoolEnvKey)
	tlsCACerts := getUserSetVarOptional(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)
	tlsServeCertPath := getUserSetVarOptional(cmd, tlsServeCertPathFlagName, tlsServeCertPathEnvKey)
	tlsServeKeyPath := getUserSetVarOptional(cmd, tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey)

	tlsSystemCertPool, err := strconv.ParseBool(tlsSystemCertPoolString)
	if err != nil {
		return nil, fmt.Errorf("parse cert pool: %w", err)
	}

	var caCerts []string
	if tlsCACerts != "" {
		caCerts = strings.Split(tlsCACerts, ",")
	}

	return &tlsParameters{
		systemCertPool: tlsSystemCertPool,
		caCerts:        caCerts,
		serveCertPath:  tlsServeCertPath,
		serveKeyPath:   tlsServeKeyPath,
	}, nil
}

func createStoreProvider(dbURL string, timeout uint64, prefix string) (storage.Provider, error) {
	driver, dsn, err := getDBParams(dbURL)
	if err != nil {
		return nil, err
	}

	providerFunc, supported := supportedStorageProviders[driver]
	if !supported {
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}

	var store storage.Provider

	return store, backoff.RetryNotify(func() error { // nolint: wrapcheck
		store, err = providerFunc(dsn, prefix)

		return err
	}, backoff.WithMaxRetries(
		backoff.NewConstantBackOff(time.Second),
		timeout,
	), func(retryErr error, t time.Duration) {
		logger.Warnf("failed to connect to storage, will sleep for %s before trying again : %v", t, retryErr)
	})
}

func getDBParams(dbURL string) (driver, dsn string, err error) {
	const urlParts = 2

	parsed := strings.SplitN(dbURL, ":", urlParts)

	if len(parsed) != urlParts {
		return "", "", fmt.Errorf("invalid dbURL %s", dbURL)
	}

	return parsed[0], strings.TrimPrefix(parsed[1], "//"), nil
}

type kmsCtx struct{ kms.KeyManager }

func (c *kmsCtx) KMS() kms.KeyManager {
	return c.KeyManager
}

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}
