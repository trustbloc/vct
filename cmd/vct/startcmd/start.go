/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	vdrweb "github.com/hyperledger/aries-framework-go/pkg/vdr/web"
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

	kmsEndpointFlagName      = "kms-endpoint"
	kmsEndpointEnvKey        = envPrefix + "KMS_ENDPOINT"
	kmsEndpointFlagShorthand = "s"
	kmsEndpointFlagUsage     = "Remote KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsEndpointEnvKey

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

	databasePrefixFlagName  = "database-prefix"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey
	databasePrefixEnvKey = envPrefix + "DATABASE_PREFIX"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = envPrefix + "TLS_SYSTEMCERTPOOL"

	autoInitTreeFlagName  = "auto-init-tree"
	autoInitTreeFlagUsage = "Creates test tree." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + autoInitTreeEnvKey
	autoInitTreeEnvKey = envPrefix + "AUTO_INIT_TREE"

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

	webKeyStoreKey      = "web-key-store"
	kidKey              = "kid"
	treeLogKey          = "tree-log"
	defaultMasterKeyURI = "local-lock://default/master/key/"
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
	autoInitTree      bool
	host              string
	logEndpoint       string
	keyID             string
	keyType           kms.KeyType
	datasourceName    string
	datasourceTimeout uint64
	databasePrefix    string
	kmsEndpoint       string
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

			autoInitTreeStr := getUserSetVarOptional(cmd, autoInitTreeFlagName, autoInitTreeEnvKey)
			autoInitTree, err := strconv.ParseBool(autoInitTreeStr)
			if err != nil {
				return fmt.Errorf("parse test tree: %w", err)
			}

			if autoInitTree {
				logger.Warnf("Log ID will be automatically created and initialized!")
			}

			logIDVal, err := getUserSetVar(cmd, logIDFlagName, logIDEnvKey, autoInitTree)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", logIDFlagName, logIDEnvKey, err)
			}

			logID, err := strconv.ParseInt(logIDVal, 10, 64)
			if !autoInitTree && err != nil {
				return fmt.Errorf("log ID is not a number: %w", err)
			}

			logEndpoint, err := getUserSetVar(cmd, logEndpointFlagName, logEndpointEnvKey, false)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", logEndpointFlagName, logEndpointEnvKey, err)
			}

			keyID := getUserSetVarOptional(cmd, keyIDFlagName, keyIDEnvKey)
			keyType := getUserSetVarOptional(cmd, keyTypeFlagName, keyTypeEnvKey)
			kmsStoreEndpoint := getUserSetVarOptional(cmd, kmsStoreEndpointFlagName, kmsStoreEndpointEnvKey)
			kmsEndpoint := getUserSetVarOptional(cmd, kmsEndpointFlagName, kmsEndpointEnvKey)
			datasourceName := getUserSetVarOptional(cmd, datasourceNameFlagName, datasourceNameEnvKey)
			databasePrefix := getUserSetVarOptional(cmd, databasePrefixFlagName, databasePrefixEnvKey)
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
				autoInitTree:      autoInitTree,
				host:              host,
				logID:             logID,
				logEndpoint:       logEndpoint,
				kmsStoreEndpoint:  kmsStoreEndpoint,
				kmsEndpoint:       kmsEndpoint,
				keyID:             keyID,
				keyType:           kms.KeyType(keyType),
				datasourceName:    datasourceName,
				databasePrefix:    databasePrefix,
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

func createKMSAndCrypto(parameters *agentParameters, client *http.Client,
	store storage.Provider, cfg storage.Store) (kms.KeyManager, crypto.Crypto, error) {
	if parameters.kmsEndpoint != "" || parameters.kmsStoreEndpoint != "" {
		if parameters.kmsStoreEndpoint != "" {
			return webkms.New(parameters.kmsStoreEndpoint, client), webcrypto.New(parameters.kmsStoreEndpoint, client), nil
		}

		var keystoreURL string

		err := getOrInit(cfg, webKeyStoreKey, &keystoreURL, func() (interface{}, error) {
			location, _, err := webkms.CreateKeyStore(client, parameters.kmsEndpoint, uuid.New().String(), "")

			return location, err // nolint: wrapcheck
		})
		if err != nil {
			return nil, nil, fmt.Errorf("get or init: %w", err)
		}

		keystoreURL = BuildKMSURL(parameters.kmsEndpoint, keystoreURL)
		parameters.kmsStoreEndpoint = keystoreURL

		return webkms.New(keystoreURL, client), webcrypto.New(keystoreURL, client), nil
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

// BuildKMSURL builds kms URL.
func BuildKMSURL(base, uri string) string {
	if strings.HasPrefix(uri, "/") {
		return base + uri
	}

	return uri
}

func createKID(km kms.KeyManager, parameters *agentParameters, cfg storage.Store) error {
	return getOrInit(cfg, kidKey, &parameters.keyID, func() (interface{}, error) {
		keyID, _, err := km.Create(parameters.keyType)

		return keyID, err // nolint: wrapcheck
	})
}

func startAgent(parameters *agentParameters) error { // nolint: funlen
	store, err := createStoreProvider(
		parameters.datasourceName,
		parameters.datasourceTimeout,
		parameters.databasePrefix,
	)
	if err != nil {
		return fmt.Errorf("create store provider: %w", err)
	}

	defer func() {
		if err = store.Close(); err != nil {
			logger.Errorf("store close: %v", err)
		}
	}()

	configStore, err := store.OpenStore("vct-config")
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	rootCAs, err := tlsutils.GetCertPool(parameters.tlsParams.systemCertPool, parameters.tlsParams.caCerts)
	if err != nil {
		return fmt.Errorf("get cert pool: %w", err)
	}

	httpClient := &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	km, cr, err := createKMSAndCrypto(parameters, httpClient, store, configStore)
	if err != nil {
		return fmt.Errorf("create kms and crypto: %w", err)
	}

	if parameters.keyID == "" {
		if err = createKID(km, parameters, configStore); err != nil {
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

	if parameters.autoInitTree {
		var tree *trillian.Tree

		tree, err = createTreeAndInit(conn, configStore)
		if err != nil {
			return fmt.Errorf("create tree: %w", err)
		}

		parameters.logID = tree.TreeId
	}

	cmd, err := command.New(&command.Config{
		Trillian: trillian.NewTrillianLogClient(conn),
		KMS:      km,
		Crypto:   cr,
		VDR: vdr.New(
			vdr.WithVDR(vdrkey.New()),
			vdr.WithVDR(&webVDR{http: httpClient, VDR: vdrweb.New()}),
		),
		LogID: parameters.logID,
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
	logger.Infof("Log ID: [%d]", parameters.logID)
	logger.Infof("Key ID: [%s]", parameters.keyID)
	logger.Infof("Store endpoint: [%s]", parameters.kmsStoreEndpoint)

	return parameters.server.ListenAndServe( // nolint: wrapcheck
		parameters.host,
		router,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
	)
}

type webVDR struct {
	http *http.Client
	*vdrweb.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return w.VDR.Read(didID, append(opts, vdrapi.WithOption(vdrweb.HTTPClientOpt, w.http))...) // nolint: wrapcheck
}

func createTreeAndInit(conn *grpc.ClientConn, cfg storage.Store) (*trillian.Tree, error) {
	var tree *trillian.Tree

	err := getOrInit(cfg, treeLogKey, &tree, func() (interface{}, error) {
		createdTree, err := trillian.NewTrillianAdminClient(conn).CreateTree(context.Background(),
			&trillian.CreateTreeRequest{
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
		if err != nil {
			return nil, fmt.Errorf("create tree: %w", err)
		}

		_, err = trillian.NewTrillianLogClient(conn).InitLog(context.Background(),
			&trillian.InitLogRequest{LogId: createdTree.TreeId},
		)

		return createdTree, err // nolint: wrapcheck
	})
	if err != nil {
		return nil, fmt.Errorf("create and init tree: %w", err)
	}

	return tree, nil
}

func getOrInit(cfg storage.Store, key string, v interface{}, initFn func() (interface{}, error)) error {
	src, err := cfg.Get(key)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("get config value for %q: %w", key, err)
	}

	if err == nil {
		return json.Unmarshal(src, v) // nolint: wrapcheck
	}

	val, err := initFn()
	if err != nil {
		return fmt.Errorf("init config value for %q: %w", key, err)
	}

	src, err = json.Marshal(val)
	if err != nil {
		return fmt.Errorf("marshal config value for %q: %w", key, err)
	}

	if err = cfg.Put(key, src); err != nil {
		return fmt.Errorf("marshal config value for %q: %w", key, err)
	}

	return getOrInit(cfg, key, v, initFn)
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
	startCmd.Flags().StringP(kmsEndpointFlagName, kmsEndpointFlagShorthand, "", kmsEndpointFlagUsage)
	startCmd.Flags().StringP(keyIDFlagName, keyIDFlagShorthand, "", keyIDFlagUsage)
	startCmd.Flags().StringP(keyTypeFlagName, keyTypeFlagShorthand, string(kms.ECDSAP256TypeIEEEP1363), keyTypeFlagUsage)
	startCmd.Flags().StringP(datasourceNameFlagName, datasourceNameFlagShorthand, "mem://test", datasourceNameFlagUsage)
	startCmd.Flags().String(databasePrefixFlagName, "", databasePrefixFlagUsage)
	startCmd.Flags().String(datasourceTimeoutFlagName, "30", datasourceTimeoutFlagUsage)
	startCmd.Flags().String(tlsSystemCertPoolFlagName, "false", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().String(tlsCACertsFlagName, "", tlsCACertsFlagUsage)
	startCmd.Flags().String(tlsServeCertPathFlagName, "", tlsServeCertPathFlagUsage)
	startCmd.Flags().String(tlsServeKeyPathFlagName, "", tlsServeKeyPathFlagUsage)
	startCmd.Flags().String(autoInitTreeFlagName, "false", autoInitTreeFlagUsage)
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
