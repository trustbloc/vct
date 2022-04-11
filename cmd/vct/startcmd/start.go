/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/trillian"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/prometheus"
	trillianstorage "github.com/google/trillian/storage"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/postgresql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	ldsvc "github.com/hyperledger/aries-framework-go/pkg/ld"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	vdrweb "github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	awssvc "github.com/trustbloc/kms/pkg/aws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/trustbloc/vct/cmd/internal/serverutil"
	"github.com/trustbloc/vct/cmd/log_server/startcmd"
	logsignerstart "github.com/trustbloc/vct/cmd/log_signer/startcmd"
	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/rest"
	"github.com/trustbloc/vct/pkg/storage/memory"
	"github.com/trustbloc/vct/pkg/storage/postgres"
)

// kmsMode kms mode.
type kmsMode string

// kms params.
const (
	kmsLocal kmsMode = "local"
	kmsWeb   kmsMode = "web"
	kmsAWS   kmsMode = "aws"

	kmsTypeFlagName  = "kms-type"
	kmsTypeEnvKey    = envPrefix + "KMS_TYPE"
	kmsTypeFlagUsage = "KMS type (local,web,aws)." +
		" Alternatively, this can be set with the following environment variable: " + kmsTypeEnvKey

	kmsEndpointFlagName  = "kms-endpoint"
	kmsEndpointEnvKey    = envPrefix + "KMS_ENDPOINT"
	kmsEndpointFlagUsage = "KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsEndpointEnvKey

	logSignActiveKeyIDFlagName  = "log-active-key-id"
	logSignActiveKeyIDEnvKey    = envPrefix + "LOG_SIGN_ACTIVE_KEY_ID"
	logSignActiveKeyIDFlagUsage = "Log Sign Active Key ID." +
		" Alternatively, this can be set with the following environment variable: " + logSignActiveKeyIDEnvKey
)

const (
	envPrefix = "VCT_"

	agentHostFlagName      = "api-host"
	agentHostEnvKey        = envPrefix + "API_HOST"
	agentHostFlagShorthand = "a"
	agentHostFlagUsage     = "Host Name:Port." +
		" Alternatively, this can be set with the following environment variable: " + agentHostEnvKey

	agentMetricsHostFlagName      = "metrics-host"
	agentMetricsHostEnvKey        = envPrefix + "METRICS_HOST"
	agentMetricsHostFlagShorthand = "m"
	agentMetricsHostFlagUsage     = "Metrics host Name:Port." +
		" Alternatively, this can be set with the following environment variable: " + agentMetricsHostEnvKey

	logsFlagName      = "logs"
	logsEnvKey        = envPrefix + "LOGS"
	logsFlagShorthand = "l"
	logsFlagUsage     = "Trillian logs comma separated. " +
		" Format must be <alias>:<permission>@<endpoint>." +
		" Examples: maple2021:rw@server.com,maple2020:r@server.com:9890" +
		" Alternatively, this can be set with the following environment variable: " + logsEnvKey

	datasourceNameFlagName      = "dsn"
	datasourceNameFlagShorthand = "d"
	datasourceNameFlagUsage     = "Datasource Name with credentials if required." +
		" Format must be <driver>:[//]<driver-specific-dsn>." +
		" Examples: 'postgres://jack:secret@pg.example.com:5432/mydb', 'mem://test'," +
		" 'mongodb://mongodb.example.com:27017'." +
		" Supported drivers are [mem, couchdb, postgres, mongodb]." +
		" Alternatively, this can be set with the following environment variable: " + datasourceNameEnvKey
	datasourceNameEnvKey = envPrefix + "DSN"

	timeoutFlagName  = "timeout"
	timeoutFlagUsage = "Total time in seconds to wait until the services are available before giving up." +
		" Alternatively, this can be set with the following environment variable: " + timeoutEnvKey
	timeoutEnvKey = envPrefix + "TIMEOUT"

	syncTimeoutFlagName  = "sync-timeout"
	syncTimeoutFlagUsage = "Total time in seconds to resolve config values." +
		" Alternatively, this can be set with the following environment variable: " + syncTimeoutEnvKey
	syncTimeoutEnvKey = envPrefix + "SYNC_TIMEOUT"

	databasePrefixFlagName  = "database-prefix"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey
	databasePrefixEnvKey = envPrefix + "DATABASE_PREFIX"

	baseURLFlagName  = "base-url"
	baseURLFlagUsage = "Base URL. e.g (https://vct.com)" +
		" Alternatively, this can be set with the following environment variable: " + baseURLEnvKey
	baseURLEnvKey = envPrefix + "BASE_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = envPrefix + "TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = envPrefix + "TLS_CACERTS"

	issuersFlagName  = "issuers"
	issuersFlagUsage = "Comma-Separated list of supported issuers." +
		" Alternatively, this can be set with the following environment variable: " + issuersEnvKey
	issuersEnvKey = envPrefix + "ISSUERS"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = envPrefix + "TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = envPrefix + "TLS_SERVE_KEY"

	devModeFlagName  = "dev-mode"
	devModeFlagUsage = "Enable dev mode." +
		" Alternatively, this can be set with the following environment variable: " + devModeFlagEnvKey
	devModeFlagEnvKey = envPrefix + "DEV_MODE"

	contextProviderFlagName  = "context-provider-url"
	contextProviderFlagUsage = "Comma-separated list of remote context provider URLs to get JSON-LD contexts from." +
		" Alternatively, this can be set with the following environment variable: " + contextProviderEnvKey
	contextProviderEnvKey = envPrefix + "CONTEXT_PROVIDER_URL"

	trillianDBConnFlagName  = "trillian-db-conn"
	trillianDBConnFlagUsage = "Trillian db conn" +
		" Alternatively, this can be set with the following environment variable: " + trillianDBConnEnvKey
	trillianDBConnEnvKey = envPrefix + "TRILLIAN_DB_CONN"

	readTokenFlagName  = "api-read-token"
	readTokenFlagUsage = "Check for bearer token in the authorization header (optional). " +
		" Alternatively, this can be set with the following environment variable: " + readTokenEnvKey
	readTokenEnvKey = envPrefix + "API_READ_TOKEN"

	writeTokenFlagName  = "api-write-token"
	writeTokenFlagUsage = "Check for bearer token in the authorization header (optional). " +
		" Alternatively, this can be set with the following environment variable: " + writeTokenEnvKey
	writeTokenEnvKey = envPrefix + "API_WRITE_TOKEN"
)

const (
	databaseTypeMemOption         = "mem"
	databaseTypePostgresSQLOption = "postgres"
	databaseTypeCouchDBOption     = "couchdb"
	databaseTypeMongoDBOption     = "mongodb"

	webKeyStoreKey        = "web-key-store"
	kidKey                = "kid"
	treeLogKey            = "tree-log"
	defaultMasterKeyURI   = "local-lock://default/master/key/"
	embeddedLogServerHost = "0.0.0.0:8090"
	embeddedLogSignerHost = "0.0.0.0:8099"
	defaultTimeout        = "0"
	defaultSyncTimeout    = "3"
	healthCheckEndpoint   = "/healthcheck"
	addVCEndpoint         = "/add-vc"
	webFingerEndpoint     = "/.well-known/webfinger"
)

type (
	// TrillianLogServer interface.
	TrillianLogServer trillian.TrillianLogServer
	// TrillianAdminServer interface.
	TrillianAdminServer trillian.TrillianAdminServer
)

type kmsParameters struct {
	kmsType            kmsMode
	kmsEndpoint        string
	logSignActiveKeyID string
}

type keyManager interface {
	Create(kt kms.KeyType) (string, interface{}, error)
	Get(keyID string) (interface{}, error)
	ExportPubKeyBytes(keyID string) ([]byte, kms.KeyType, error)
}

type crypto interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

var logger = log.New("vct/startcmd")

// nolint:gochecknoglobals
var supportedStorageProviders = map[string]func(string, string) (storage.Provider, error){
	databaseTypeCouchDBOption: func(dsn, prefix string) (storage.Provider, error) {
		return couchdb.NewProvider(dsn, couchdb.WithDBPrefix(prefix)) // nolint: wrapcheck
	},
	databaseTypeMongoDBOption: func(dsn, prefix string) (storage.Provider, error) {
		return mongodb.NewProvider("mongodb://"+dsn, mongodb.WithDBPrefix(prefix)) // nolint: wrapcheck
	},
	databaseTypePostgresSQLOption: func(dsn, prefix string) (storage.Provider, error) {
		p, err := postgresql.NewProvider("postgres://"+dsn, postgresql.WithDBPrefix(prefix))
		if err != nil {
			return nil, err
		}

		return p, nil
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

// StorageProvider represents a storage provider.
type StorageProvider storage.Provider

// Cmd returns the Cobra start command.
func Cmd(server server) (*cobra.Command, error) {
	startCmd := createStartCMD(server)

	createFlags(startCmd)

	return startCmd, nil
}

type agentParameters struct {
	logs                []command.Log
	host                string
	metricsHost         string
	baseURL             string
	datasourceName      string
	timeout             uint64
	syncTimeout         uint64
	databasePrefix      string
	contextProviderURLs []string
	tlsParams           *tlsParameters
	server              server
	devMode             bool
	kmsParams           *kmsParameters
	readToken           string
	writeToken          string
}

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

func parseLogs(logsRaw string, issuersRaw []string) ([]command.Log, bool) { //nolint:funlen
	logsSet := map[string]command.Log{}

	issuersSet := map[string]map[string]struct{}{}

	starTrillian := false

	for _, issuerRaw := range issuersRaw {
		parts := strings.Split(issuerRaw, "@")

		alias := strings.TrimSpace(parts[0])
		issuer := strings.TrimSpace(parts[1])

		if _, ok := issuersSet[alias]; !ok {
			issuersSet[alias] = map[string]struct{}{}
		}

		issuersSet[alias][issuer] = struct{}{}
	}

	for _, rawLog := range strings.Split(logsRaw, ",") {
		var alias string

		var permission string

		var endpoint string

		if strings.Contains(rawLog, "@") {
			parts := strings.Split(rawLog, "@")
			apParts := strings.Split(parts[0], ":")

			alias = apParts[0]
			permission = apParts[1]
			endpoint = parts[1]
		} else {
			parts := strings.Split(rawLog, ":")
			alias = parts[0]
			permission = parts[1]
			endpoint = embeddedLogServerHost
			starTrillian = true
		}

		logEntity := command.Log{
			Alias:      strings.TrimSpace(alias),
			Permission: strings.TrimSpace(permission),
			Endpoint:   strings.TrimSpace(endpoint),
		}

		var issuers []string
		for issuer := range issuersSet[logEntity.Alias] {
			issuers = append(issuers, issuer)
		}

		logEntity.Issuers = issuers

		logsSet[logEntity.Alias] = logEntity
	}

	var result []command.Log
	for _, v := range logsSet {
		result = append(result, v)
	}

	return result, starTrillian
}

func createStartCMD(server server) *cobra.Command { //nolint: funlen,gocognit,gocyclo,cyclop
	return &cobra.Command{
		Use:   "start",
		Short: "Starts vct service",
		Long:  `Starts verifiable credentials transparency service`,
		RunE: func(cmd *cobra.Command, args []string) error {
			host := cmdutils.GetUserSetOptionalVarFromString(cmd, agentHostFlagName, agentHostEnvKey)
			metricsHost := cmdutils.GetUserSetOptionalVarFromString(cmd, agentMetricsHostFlagName,
				agentMetricsHostEnvKey)
			datasourceName := cmdutils.GetUserSetOptionalVarFromString(cmd, datasourceNameFlagName,
				datasourceNameEnvKey)
			databasePrefix := cmdutils.GetUserSetOptionalVarFromString(cmd, databasePrefixFlagName,
				databasePrefixEnvKey)
			baseURL := cmdutils.GetUserSetOptionalVarFromString(cmd, baseURLFlagName, baseURLEnvKey)
			timeoutStr := cmdutils.GetUserSetOptionalVarFromString(cmd, timeoutFlagName, timeoutEnvKey)
			syncTimeoutStr := cmdutils.GetUserSetOptionalVarFromString(cmd, syncTimeoutFlagName, syncTimeoutEnvKey)
			issuersStr := cmdutils.GetUserSetOptionalVarFromString(cmd, issuersFlagName, issuersEnvKey)
			devModeStr := cmdutils.GetUserSetOptionalVarFromString(cmd, devModeFlagName, devModeFlagEnvKey)
			contextProviderURLsStr := cmdutils.GetUserSetOptionalVarFromString(cmd, contextProviderFlagName,
				contextProviderEnvKey)
			trillianDBConnStr := cmdutils.GetUserSetOptionalVarFromString(cmd, trillianDBConnFlagName,
				trillianDBConnEnvKey)
			kmsParams, err := getKmsParameters(cmd)
			if err != nil {
				return err
			}

			readToken := cmdutils.GetUserSetOptionalVarFromString(cmd, readTokenFlagName, readTokenEnvKey)
			writeToken := cmdutils.GetUserSetOptionalVarFromString(cmd, writeTokenFlagName, writeTokenEnvKey)

			if datasourceName == "" {
				datasourceName = "mem://test"
			}

			var issuers []string
			if issuersStr != "" {
				issuers = strings.Split(issuersStr, ",")
			}

			var contextProviderURLs []string
			if contextProviderURLsStr != "" {
				contextProviderURLs = strings.Split(contextProviderURLsStr, ",")
			}

			if timeoutStr == "" {
				timeoutStr = defaultTimeout
			}

			timeout, err := strconv.ParseUint(timeoutStr, 10, 64)
			if err != nil {
				return fmt.Errorf("timeout is not a number(positive): %w", err)
			}

			if syncTimeoutStr == "" {
				syncTimeoutStr = defaultSyncTimeout
			}

			syncTimeout, err := strconv.ParseUint(syncTimeoutStr, 10, 64)
			if err != nil {
				return fmt.Errorf("sync timeout is not a number(positive): %w", err)
			}

			tlsParams, err := getTLS(cmd)
			if err != nil {
				return fmt.Errorf("get TLS: %w", err)
			}

			logsVal, err := cmdutils.GetUserSetVarFromString(cmd, logsFlagName, logsEnvKey, false)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", logsFlagName, logsEnvKey, err)
			}

			devMode := false

			if devModeStr != "" {
				devMode, err = strconv.ParseBool(devModeStr)
				if err != nil {
					return fmt.Errorf("dev mode is not a bool: %w", err)
				}
			}

			logs, starTrillian := parseLogs(logsVal, issuers)

			if starTrillian { //nolint: nestif
				if err := trillianstorage.RegisterProvider("mem", memory.NewMemoryStorageProvider); err != nil {
					logger.Errorf(err.Error())
				}

				postgres.PGConnStr = trillianDBConnStr

				if err := trillianstorage.RegisterProvider("postgres", postgres.NewPGProvider); err != nil {
					logger.Errorf(err.Error())
				}

				go func() {
					startCMD := startcmd.CMD{
						RPCEndpoint:              embeddedLogServerHost,
						ETCDService:              "trillian-logserver",
						QuotaSystem:              "noop",
						StorageSystem:            "mem",
						TreeDeleteThreshold:      serverutil.DefaultTreeDeleteThreshold,
						TreeDeleteMinRunInterval: serverutil.DefaultTreeDeleteMinInterval,
					}

					if trillianDBConnStr != "" {
						startCMD.PGConnStr = trillianDBConnStr
						startCMD.StorageSystem = "postgres"
					}

					// start log server
					if err := startCMD.Start(); err != nil {
						panic(err)
					}
				}()

				go func() {
					startCMD := logsignerstart.CMD{
						RPCEndpoint:           embeddedLogSignerHost,
						HealthzTimeout:        5 * time.Second,        //nolint: gomnd
						SequencerIntervalFlag: 100 * time.Millisecond, //nolint: gomnd
						QuotaSystem:           "noop",
						BatchSizeFlag:         1000, //nolint: gomnd
						StorageSystem:         "mem",
						NumSeqFlag:            10, //nolint: gomnd
						ForceMaster:           true,
						PREElectionPause:      1 * time.Second,
					}

					if trillianDBConnStr != "" {
						startCMD.PGConnStr = trillianDBConnStr
						startCMD.StorageSystem = "postgres"
					}

					// start log signer
					if err := startCMD.Start(); err != nil {
						panic(err)
					}
				}()
			}

			parameters := &agentParameters{
				server:              server,
				host:                host,
				metricsHost:         metricsHost,
				logs:                logs,
				timeout:             timeout,
				syncTimeout:         syncTimeout,
				datasourceName:      datasourceName,
				databasePrefix:      databasePrefix,
				tlsParams:           tlsParams,
				baseURL:             baseURL,
				devMode:             devMode,
				contextProviderURLs: contextProviderURLs,
				kmsParams:           kmsParams,
				readToken:           readToken,
				writeToken:          writeToken,
			}

			return startAgent(parameters)
		},
	}
}

func createKMSAndCrypto(parameters *agentParameters, client *http.Client,
	store storage.Provider, cfg storage.Store, mf monitoring.MetricFactory) (keyManager, crypto, error) {
	switch parameters.kmsParams.kmsType {
	case kmsLocal:
		km, err := localkms.New(defaultMasterKeyURI, &kmsProvider{
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

		return km, cr, nil
	case kmsWeb:
		if strings.Contains(parameters.kmsParams.kmsEndpoint, "keystores") {
			return webkms.New(parameters.kmsParams.kmsEndpoint, client),
				webcrypto.New(parameters.kmsParams.kmsEndpoint, client), nil
		}

		var keystoreURL string

		err := getOrInit(cfg, webKeyStoreKey, &keystoreURL, func() (interface{}, error) {
			location, _, err := webkms.CreateKeyStore(client, parameters.kmsParams.kmsEndpoint, uuid.New().String(), "", nil)

			return location, err
		}, parameters.syncTimeout)
		if err != nil {
			return nil, nil, fmt.Errorf("get or init: %w", err)
		}

		keystoreURL = BuildKMSURL(parameters.kmsParams.kmsEndpoint, keystoreURL)

		return webkms.New(keystoreURL, client), webcrypto.New(keystoreURL, client), nil
	case kmsAWS:
		region, err := getRegion(parameters.kmsParams.logSignActiveKeyID)
		if err != nil {
			return nil, nil, err
		}

		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &parameters.kmsParams.kmsEndpoint,
			Region:                        aws.String(region),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		if err != nil {
			return nil, nil, err
		}

		awsSvc := awssvc.New(awsSession, NewAWSMetricsProvider(mf))

		return awsSvc, awsSvc, nil
	}

	return nil, nil, fmt.Errorf("unsupported kms type: %s", parameters.kmsParams.kmsType)
}

func getRegion(keyURI string) (string, error) {
	// keyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
	// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
	re1 := regexp.MustCompile(`aws-kms://arn:(aws[a-zA-Z0-9-_]*):kms:([a-z0-9-]+):`)

	r := re1.FindStringSubmatch(keyURI)

	const subStringCount = 3

	if len(r) != subStringCount {
		return "", fmt.Errorf("extracting region from URI failed")
	}

	return r[2], nil
}

func getKmsParameters(cmd *cobra.Command) (*kmsParameters, error) {
	kmsTypeStr, err := cmdutils.GetUserSetVarFromString(cmd, kmsTypeFlagName, kmsTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	kmsType := kmsMode(kmsTypeStr)

	if !supportedKmsType(kmsType) {
		return nil, fmt.Errorf("unsupported kms type: %s", kmsType)
	}

	kmsEndpoint := cmdutils.GetUserSetOptionalVarFromString(cmd, kmsEndpointFlagName, kmsEndpointEnvKey)
	logSignActiveKeyID := cmdutils.GetUserSetOptionalVarFromString(cmd, logSignActiveKeyIDFlagName,
		logSignActiveKeyIDEnvKey)

	return &kmsParameters{
		kmsType:            kmsType,
		kmsEndpoint:        kmsEndpoint,
		logSignActiveKeyID: logSignActiveKeyID,
	}, nil
}

func supportedKmsType(kmsType kmsMode) bool {
	if kmsType != kmsLocal && kmsType != kmsWeb && kmsType != kmsAWS {
		return false
	}

	return true
}

// BuildKMSURL builds kms URL.
func BuildKMSURL(base, uri string) string {
	if strings.HasPrefix(uri, "/") {
		return base + uri
	}

	return uri
}

func createKID(km keyManager, cfg storage.Store, syncTimeout uint64) (string, error) {
	var (
		keyID   string
		keyType = kms.ECDSAP256TypeIEEEP1363
	)

	err := getOrInit(cfg, kidKey, &keyID, func() (interface{}, error) {
		kid, _, err := km.Create(keyType)

		return kid, err // nolint: wrapcheck
	}, syncTimeout)

	return keyID, err
}

func startAgent(parameters *agentParameters) error { //nolint:funlen,gocyclo,cyclop,gocognit
	store, err := createStoreProvider(
		parameters.datasourceName,
		parameters.databasePrefix,
		parameters.timeout,
	)
	if err != nil {
		return fmt.Errorf("create store provider: %w", err)
	}

	defer func() {
		if err = store.Close(); err != nil {
			logger.Errorf("store close: %v", err)
		}
	}()

	configStore, err := store.OpenStore("config")
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
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	mf := prometheus.MetricFactory{}

	km, cr, err := createKMSAndCrypto(parameters, httpClient, store, configStore, mf)
	if err != nil {
		return fmt.Errorf("create kms and crypto: %w", err)
	}

	keyID := parameters.kmsParams.logSignActiveKeyID

	if keyID == "" {
		keyID, err = createKID(km, configStore, parameters.syncTimeout)
		if err != nil {
			return fmt.Errorf("create kid: %w", err)
		}
	}

	var aliases []string

	conns := map[string]*grpc.ClientConn{}

	for i := range parameters.logs {
		var tree *trillian.Tree

		conn, ok := conns[parameters.logs[i].Endpoint]
		if !ok {
			conn, err = grpc.Dial(parameters.logs[i].Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return fmt.Errorf("grpc dial: %w", err)
			}

			conns[parameters.logs[i].Endpoint] = conn
		}

		tree, err = createTreeAndInit(conn, configStore, parameters.logs[i].Alias,
			parameters.timeout, parameters.syncTimeout)
		if err != nil {
			return fmt.Errorf("create tree: %w", err)
		}

		parameters.logs[i].ID = tree.TreeId
		parameters.logs[i].Client = trillian.NewTrillianLogClient(conn)

		aliases = append(aliases, parameters.logs[i].Alias)
	}

	defer func() {
		for _, conn := range conns {
			conn.Close() // nolint: errcheck,gosec
		}
	}()

	loaders := map[string]jsonld.DocumentLoader{}
	ldStoreProviders := map[string]*ldStoreProvider{}

	for _, alias := range aliases {
		storageProvider := &customizedStorageProvider{
			alias:           strings.ReplaceAll(alias, "-", "_"),
			StorageProvider: store,
		}

		ldStore, er := createLDStoreProvider(storageProvider)
		if er != nil {
			return fmt.Errorf("create ld store provider: %w", er)
		}

		loader, er := createJSONLDDocumentLoader(ldStore, httpClient, parameters.contextProviderURLs)
		if er != nil {
			return fmt.Errorf("create document loader: %w", er)
		}

		loaders[alias] = loader
		ldStoreProviders[alias] = ldStore
	}

	cmd, err := command.New(&command.Config{
		KMS:    km,
		Crypto: cr,
		VDR: vdr.New(
			vdr.WithVDR(vdrkey.New()),
			vdr.WithVDR(&webVDR{http: httpClient, VDR: vdrweb.New(), useHTTPOpt: parameters.devMode}),
		),
		Logs: parameters.logs,
		Key: command.Key{
			ID: keyID,
		},
		BaseURL:         parameters.baseURL,
		DocumentLoaders: loaders,
	}, mf)
	if err != nil {
		return fmt.Errorf("create command instance: %w", err)
	}

	var (
		router        = mux.NewRouter()
		metricsRouter = mux.NewRouter()
	)

	for _, handler := range rest.New(cmd, mf).GetRESTHandlers() {
		if handler.Path() == rest.MetricsPath {
			metricsRouter.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
		} else {
			router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
		}
	}

	for alias, ldStore := range ldStoreProviders {
		r := router.PathPrefix(strings.ReplaceAll(rest.BasePath, rest.AliasPath, "/"+alias)).Subrouter()

		// handlers for JSON-LD context operations
		for _, handler := range ldrest.New(ldsvc.New(ldStore)).GetRESTHandlers() {
			r.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
		}
	}

	if parameters.readToken != "" || parameters.writeToken != "" {
		router.Use(authorizationMiddleware(parameters.readToken, parameters.writeToken))
	}

	go startMetrics(parameters, metricsRouter)

	logger.Infof("Starting vct on host [%s]", parameters.host)

	return parameters.server.ListenAndServe( // nolint: wrapcheck
		parameters.host,
		cors.New(cors.Options{AllowedMethods: []string{http.MethodGet, http.MethodPost}}).Handler(router),
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
	)
}

func startMetrics(parameters *agentParameters, route *mux.Router) {
	err := parameters.server.ListenAndServe(parameters.metricsHost, route, "", "")
	if err != nil {
		logger.Fatalf("%v", err)
	}
}

type webVDR struct {
	http *http.Client
	*vdrweb.VDR
	useHTTPOpt bool
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	if w.useHTTPOpt {
		opts = append(opts, vdrapi.WithOption(vdrweb.UseHTTPOpt, true))
	}

	return w.VDR.Read(didID, append(opts, vdrapi.WithOption(vdrweb.HTTPClientOpt, w.http))...) // nolint: wrapcheck
}

func createTreeAndInit(conn *grpc.ClientConn, cfg storage.Store, alias string, timeout,
	syncTimeout uint64) (*trillian.Tree, error) {
	var tree *trillian.Tree

	err := getOrInit(cfg, treeLogKey+"-"+alias, &tree, func() (interface{}, error) {
		var (
			createdTree *trillian.Tree
			err         error
		)

		err = backoff.RetryNotify(func() error {
			createdTree, err = trillian.NewTrillianAdminClient(conn).CreateTree(context.Background(),
				&trillian.CreateTreeRequest{
					Tree: &trillian.Tree{
						TreeState:       trillian.TreeState_ACTIVE,
						TreeType:        trillian.TreeType_LOG,
						MaxRootDuration: durationpb.New(time.Hour),
					},
				})

			return err // nolint: wrapcheck
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), timeout), func(err error, duration time.Duration) {
			logger.Warnf("create tree failed, will sleep for %v before trying again: %v", duration, err)
		})

		if err != nil {
			return nil, fmt.Errorf("create tree: %w", err)
		}

		_, err = trillian.NewTrillianLogClient(conn).InitLog(context.Background(),
			&trillian.InitLogRequest{LogId: createdTree.TreeId},
		)

		return createdTree, err // nolint: wrapcheck
	}, syncTimeout)
	if err != nil {
		return nil, fmt.Errorf("create and init tree: %w", err)
	}

	return tree, nil
}

func getOrInit(cfg storage.Store, key string, v interface{}, initFn func() (interface{}, error), timeout uint64) error {
	src, err := cfg.Get(key)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("get config value for %q: %w", key, err)
	}

	if err == nil {
		time.Sleep(time.Second * time.Duration(timeout))

		var src2 []byte

		src2, err = cfg.Get(key)
		if err != nil && errors.Is(err, storage.ErrDataNotFound) {
			return getOrInit(cfg, key, v, initFn, timeout)
		}

		if err != nil {
			return fmt.Errorf("get config value for %q: %w", key, err)
		}

		if reflect.DeepEqual(src, src2) {
			return json.Unmarshal(src, v) // nolint: wrapcheck
		}

		return getOrInit(cfg, key, v, initFn, timeout)
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

	return getOrInit(cfg, key, v, initFn, timeout)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(agentHostFlagName, agentHostFlagShorthand, ":5678", agentHostFlagUsage)
	startCmd.Flags().StringP(agentMetricsHostFlagName, agentMetricsHostFlagShorthand, ":9099", agentMetricsHostFlagUsage)
	startCmd.Flags().StringP(logsFlagName, logsFlagShorthand, "", logsFlagUsage)
	startCmd.Flags().StringP(datasourceNameFlagName, datasourceNameFlagShorthand, "mem://test", datasourceNameFlagUsage)
	startCmd.Flags().String(databasePrefixFlagName, "", databasePrefixFlagUsage)
	startCmd.Flags().String(baseURLFlagName, "", baseURLFlagUsage)
	startCmd.Flags().String(timeoutFlagName, "0", timeoutFlagUsage)
	startCmd.Flags().String(syncTimeoutFlagName, "3", syncTimeoutFlagUsage)
	startCmd.Flags().String(tlsSystemCertPoolFlagName, "false", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().String(tlsCACertsFlagName, "", tlsCACertsFlagUsage)
	startCmd.Flags().String(tlsServeCertPathFlagName, "", tlsServeCertPathFlagUsage)
	startCmd.Flags().String(tlsServeKeyPathFlagName, "", tlsServeKeyPathFlagUsage)
	startCmd.Flags().String(issuersFlagName, "", issuersFlagUsage)
	startCmd.Flags().String(devModeFlagName, "", devModeFlagUsage)
	startCmd.Flags().String(contextProviderFlagName, "", contextProviderFlagUsage)
	startCmd.Flags().String(trillianDBConnFlagName, "", trillianDBConnFlagUsage)
	startCmd.Flags().String(kmsTypeFlagName, "", kmsTypeFlagUsage)
	startCmd.Flags().String(kmsEndpointFlagName, "", kmsEndpointFlagUsage)
	startCmd.Flags().String(logSignActiveKeyIDFlagName, "", logSignActiveKeyIDFlagUsage)
	startCmd.Flags().String(readTokenFlagName, "", readTokenFlagUsage)
	startCmd.Flags().String(writeTokenFlagName, "", writeTokenFlagUsage)
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)
	tlsCACerts := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)
	tlsServeCertPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeCertPathFlagName, tlsServeCertPathEnvKey)
	tlsServeKeyPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsServeKeyPathFlagName, tlsServeKeyPathFlagEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error

		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, fmt.Errorf("parse cert pool: %w", err)
		}
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

func createStoreProvider(dbURL, prefix string, timeout uint64) (storage.Provider, error) {
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

type customizedStorageProvider struct {
	alias string
	StorageProvider
}

func (p *customizedStorageProvider) OpenStore(name string) (storage.Store, error) {
	return p.StorageProvider.OpenStore(p.alias + name)
}

func (p *customizedStorageProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	return p.StorageProvider.SetStoreConfig(p.alias+name, config)
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

func createLDStoreProvider(provider storage.Provider) (*ldStoreProvider, error) {
	contextStore, err := ldstore.NewContextStore(provider)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(provider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	return &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}, nil
}

func createJSONLDDocumentLoader(ldStore *ldStoreProvider, httpClient *http.Client,
	providerURLs []string) (jsonld.DocumentLoader, error) {
	var loaderOpts []ld.DocumentLoaderOpts

	for _, u := range providerURLs {
		loaderOpts = append(loaderOpts,
			ld.WithRemoteProvider(
				remote.NewProvider(u, remote.WithHTTPClient(httpClient)),
			),
		)
	}

	loader, err := ld.NewDocumentLoader(ldStore, loaderOpts...)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return loader, nil
}

// ValidateAuthorizationBearerToken validate token.
func ValidateAuthorizationBearerToken(w http.ResponseWriter, r *http.Request, readToken, writeToken string) bool {
	if r.RequestURI == healthCheckEndpoint || strings.Contains(r.RequestURI, webFingerEndpoint) {
		return true
	}

	token := readToken

	if strings.Contains(r.RequestURI, addVCEndpoint) {
		if writeToken == "" {
			return true
		}

		token = writeToken
	}

	if token != "" {
		actHdr := r.Header.Get("Authorization")
		expHdr := "Bearer " + token

		if subtle.ConstantTimeCompare([]byte(actHdr), []byte(expHdr)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorised.\n")) // nolint:gosec,errcheck

			return false
		}
	}

	return true
}

func authorizationMiddleware(readToken, writeToken string) mux.MiddlewareFunc {
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ValidateAuthorizationBearerToken(w, r, readToken, writeToken) {
				next.ServeHTTP(w, r)
			}
		})
	}

	return middleware
}

// AWSMetricsProvider aws metrics provider.
type AWSMetricsProvider struct {
	signCount            monitoring.Counter
	signTime             monitoring.Histogram
	exportPublicKeyCount monitoring.Counter
	exportPublicKeyTime  monitoring.Histogram
}

// NewAWSMetricsProvider return new instance.
func NewAWSMetricsProvider(mf monitoring.MetricFactory) *AWSMetricsProvider {
	if mf == nil {
		mf = monitoring.InertMetricFactory{}
	}

	signCount := mf.NewCounter("aws_sign_count", "AWS sign count")
	signTime := mf.NewHistogram("aws_sign_seconds", "AWS sign time")
	exportPublicKeyCount := mf.NewCounter("aws_export_publickey_count", "AWS export public key count")
	exportPublicKeyTime := mf.NewHistogram("aws_export_publickey_seconds", "AWS export public key time")

	return &AWSMetricsProvider{
		signCount:            signCount,
		signTime:             signTime,
		exportPublicKeyCount: exportPublicKeyCount,
		exportPublicKeyTime:  exportPublicKeyTime,
	}
}

// SignCount increments the number of sign hits.
func (a *AWSMetricsProvider) SignCount() {
	a.signCount.Inc()
}

// SignTime records the time for sign.
func (a *AWSMetricsProvider) SignTime(value time.Duration) {
	a.signTime.Observe(value.Seconds())
}

// ExportPublicKeyCount increments the number of export public key hits.
func (a *AWSMetricsProvider) ExportPublicKeyCount() {
	a.exportPublicKeyCount.Inc()
}

// ExportPublicKeyTime records the time for export public key.
func (a *AWSMetricsProvider) ExportPublicKeyTime(value time.Duration) {
	a.exportPublicKeyTime.Observe(value.Seconds())
}

// VerifyCount increments the number of verify hits.
func (a *AWSMetricsProvider) VerifyCount() {}

// VerifyTime records the time for verify.
func (a *AWSMetricsProvider) VerifyTime(value time.Duration) {}
