package api

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	mem "github.com/hyperledger/fabric/membersrvc/protos"
	eu "github.com/hyperledger/fabric/sdk/golang/util"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

var ( // sk of registar

	registarPriv = `-----BEGIN PRIVATE KEY-----
MHcCAQEEIOjU658gDAcHuEz3/BIf0cl1qFy/i3kaTZ8vm7jo5yMdoAoGCCqGSM49
AwEHoUQDQgAEni/QNcCABD4qjIQcCy5FJ22U2njKiusj0vG9q0pZ/5nKYLcDspG3
PZpT/yUchv1eBRzgVkeYiORDX3fXyIDf3g==
-----END PRIVATE KEY-----`

	registarSK *ecdsa.PrivateKey
)

var ( // pk of chain, for encrypt transaction

	chainKey = `-----BEGIN ECDSA PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqhhpywj5AyUPYrvpg9KD9fLpUVFk
9pPj4sTBK0yU9CHUhH16+mlLcFPXWcyL9JfU3mK+m8I8vQ9N7kKluVxGVg==
-----END ECDSA PUBLIC KEY-----`

	chainPk *ecdsa.PublicKey
)

func init() {

	format := logging.MustStringFormatter(`[%{module}] %{time:2006-01-02 15:04:05} [%{level}] [%{longpkg} %{shortfile}] { %{message} }`)

	backendConsole := logging.NewLogBackend(os.Stderr, "", 0)
	backendConsole2Formatter := logging.NewBackendFormatter(backendConsole, format)

	logging.SetBackend(backendConsole2Formatter)

	viper.SetConfigName("api")
	viper.AddConfigPath("./")
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatalf("Fatal error when reading %s config file: %s\n", "asset.yaml", err)
	}

	if err := primitives.InitSecurityLevel(viper.GetString("security.hashAlgorithm"), viper.GetInt("security.level")); err != nil {
		logger.Fatal(err)
	}

	Init()

	// for registar sk
	block, _ := pem.Decode([]byte(registarPriv))
	if block == nil {
		logger.Fatal("pem.Decode return nil")
	}

	var err error
	registarSK, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		logger.Fatal(err)
	}

	// for chain pk
	block, _ = pem.Decode([]byte(chainKey))
	if block == nil {
		logger.Fatal("pem.Decode return nil")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.Fatal(err)
	}

	var ok bool
	if chainPk, ok = pub.(*ecdsa.PublicKey); !ok {
		logger.Fatal("chainKey is not in format of ecdsa")
	}
}

func Test(t *testing.T) {

	//	/* -------------------create, eca cert-pairs, only allow once------------- */
	//	doGetEnrollmentData()

	//	/* -------------------register new user------------------ */
	//	doRegister()

	//	/* -------------------get t-certs ----------------------- */
	//	doGetTCertsFromTCA()

	//	/* -------------------deploy chaincode------------------- */
	//	doDeploy()

	//	/* -------------------invoke transaction----------------- */
	//	doInvoke()

	//	/* -------------------query data------------------------- */
	//	doQuery()

	doRest()
}

func doGetEnrollmentData() {

	/*get eca and tlsca*/
	GetEnrollmentData("admin", "Xurw3yU9zI0l", GetEcaChainCert())
}

func doRegister() {

	req := &mem.RegisterUserReq{
		Id:   &mem.Identity{Id: "minami"},
		Role: mem.Role(1),
		Attributes: []*mem.Attribute{
			&mem.Attribute{
				Name:      "oper",
				Value:     "transfer",
				NotBefore: "2015-01-01T00:00:00-03:00",
			},
		},
		Affiliation: "institution_a",
		Registrar: &mem.Registrar{
			Id: &mem.Identity{Id: "admin"},
		},
		Sig: nil}

	_, err := Register(req, registarSK)
	if err != nil {
		logger.Fatal(err)
	}
}

func doGetTCertsFromTCA() (*ecdsa.PrivateKey, []byte, error) {

	/*get t-cert pairs*/
	_, tCerts, err := GetTCertsFromTCA("admin", registarSK, nil, 2, GetTcaChainCert())
	if err != nil {
		logger.Fatal(err)
	}

	if len(tCerts) == 0 {
		logger.Fatal("get Tcerts from tca failed")
	}

	sk, err := eu.ParshSK(tCerts[0]["sk"])
	if err != nil {
		logger.Fatal(err)
	}

	block, _ := pem.Decode([]byte(tCerts[0]["cert"]))
	if block == nil {
		logger.Fatal("pem.Decode return nil")
	}
	rawCrt := block.Bytes

	return sk, rawCrt, nil
}

func doDeploy() {
	//	viper.SetDefault("proxy.address", "172.17.0.1:4000")

	tSk, tCrt, _ := doGetTCertsFromTCA()

	path := "github.com/hyperledger/fabric/sdk/golang/chaincode"
	args := []string{"init", "deploy chaincode"}

	Deploy(path, args, []byte("dummy metadata"), tSk, tCrt, chainPk)
}

func doInvoke() {

	tSk, tCrt, _ := doGetTCertsFromTCA()

	path := ""
	args := []string{"invoke", "Pt999", "7.7g"}
	txid, err := eu.GenerateUUID()
	if err != nil {
		logger.Fatal(err)
	}

	Invoke(path, args, txid, []byte("dummy metadata"), tSk, tCrt, chainPk)
}

func doQuery() {

	tSk, tCrt, _ := doGetTCertsFromTCA()

	path := ""
	args := []string{"query", "Pt999"}
	txid, err := eu.GenerateUUID()
	if err != nil {
		logger.Fatal(err)
	}

	Query(path, args, txid, []byte("dummy metadata"), tSk, tCrt, chainPk)
}

func doRest() {
	var payload string
	var err error

	if payload, err = Chain(); err != nil {
		logger.Fatal(err)
	} else {
		logger.Info("chain", payload)
	}

	if payload, err = ChainBlocks(1); err != nil {
		logger.Fatal(err)
	} else {
		logger.Info("chainblocks", payload)
	}

	if payload, err = Transactions("7d411b87-0fbe-41f8-845a-3abac6631800"); err != nil {
		logger.Fatal(err)
	} else {
		logger.Info("transactions", payload)
	}

	if payload, err = Network(); err != nil {
		logger.Fatal(err)
	} else {
		logger.Info("network", payload)
	}
}
