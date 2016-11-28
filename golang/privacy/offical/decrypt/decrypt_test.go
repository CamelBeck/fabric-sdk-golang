package decrypt

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/op/go-logging"
)

const ( // sk of chain, for decrypt transaction

	chainKey = `-----BEGIN ECDSA PRIVATE KEY-----
MHcCAQEEIGPh4s6CzYtIWLMj9TdtrnHoUfJr3gQDU3O307SdTaZsoAoGCCqGSM49
AwEHoUQDQgAEliN7kTaC2P2GHsJZs/ZphlNKbQmHjCXOiPEaeRMkbfbr4c04R6Cl
9AYv5md1J4Xo+nbz/VX2Qtu7UDzwfDMQeQ==
-----END ECDSA PRIVATE KEY-----`
)

const (
	transaction = `{
  "type": 2,
  "chaincodeID": "BFl62fq1T3pwPcsd7vo///Gmn2sAtL6xSxXR5rv0NtNxcDiOfPADAK/5i3DTteBycyoVc2Fl29W6pqnXVXocHMmZb95IN2Btx0HgFIcbL1zl2VYGUF4YnDlGG7PY6yAEAYi/jd4Wnuenus5jlftP6ZyJFZQU62S5Efdis+d+UeIiuFx7Xnx/ZRSep2P5bYVR/8G86D/9UajkYm6kYR23QKZZ/0AErB2SKl6X3cR+NG/3grOS2jgXQ4CRz55oaoPpt8xwMt4he6flF6WvyQlCTWbrf23T6F3RJJRWj8qwU8kVvGvLQ66bTT0kyMFlX6Yym7h1KA==",
  "payload": "BPUV7+/JwN5Mi+BZIkmRQE+wkBUHmZ68M4D4qd8EZvm9HirrmihAOi46MPLj+3niLobjhhoTVSvcCcBzym7ULpV/LRZa4Xw7dqTgvqNEfee1o0gHvdv6+T7rdlUptmp/VhV0IRADPhdYHUMcRZExC7ewyEr7Q0u5Ucmsz4HyrKA9zrbVnudVADhxiNzXqcF2ONzrWklizmafvjpIxqzL15WCH77V8Crb75OhviNkfoCb1vQO7mqsVnicOlYP6NpqbL2ufmnRDj6UFOTO+NVmp4HWLIZjNDRk5FCI+0m2Z/Yv5+MmfjM4NZIEGgUsBwvtt3q4YL4o6FjknFOYvxrgiYJsZ/27b/YrRMReFdtQehQSRBtFwnkVBzMuQApV3AUSzdOdOiTwNHGW1pxIlcx+kZuGuTggbLKoz9pFtg==",
  "metadata": "BNJjDMWykbyPTFNvAhPV5CQLoDpurowobo08Ro9DgIDL6I5ELOmbAhNZc5TxJUgjr/yIIk2p5uoTXqw91sezEV+koAtDPxlPb6Fe4gFXDO//0w9Vqxhqnp9p0FlLBYhBFf6gbuGIjwudlLblGyRqhHFziWtoz2X3Mz8a9N1IUw==",
  "txid": "xxx-xxxxx-xxxxx-i001",
  "timestamp": {
    "seconds": 1473313535,
    "nanos": 717669994
  },
  "confidentialityLevel": 1,
  "confidentialityProtocolVersion": "1.2",
  "nonce": "QB6lZXuD8r8QWCO7GYNEWppCv0seOGVM",
  "toValidators": "BHjkdN9pvAdCgK3HHl5+5XHqShtGMU+wtGAB0mGzYDyt7T3rDVQTguNwU+b8Ehcvco8i5t8IjL9poEDvd3AQHRCY0WolrUqwxWsrPLmxbpf2dR8eUsUV6Agjdt0nMhSyrFCVg9xR0ZmB/uQ7k4vCk1LjLpcxFVt7oBlAhASr8DyaX5Vh08jxgBZbp/E82o4SrX9Zip3TJR1GmN1LkH7X11lkUtUiIfpap2yf5r0FNLM8lGHJmAKPk8bwRgs+OUb7OBnVEtuACOP/uhvYVFG8n3tL2tRPdKP2IuuCUKXPKaQOF940XU9ewR+bTCTF/ZN1",
  "cert": "MIIBsTCCAVegAwIBAgIBATAKBggqhkjOPQQDAzAxMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLSHlwZXJsZWRnZXIxDDAKBgNVBAMTA2VjYTAeFw0xNjA5MDgwNTQxMTJaFw0xNjEyMDcwNTQxMTJaMEExCzAJBgNVBAYTAlVTMRQwEgYDVQQKEwtIeXBlcmxlZGdlcjEcMBoGA1UEAwwTYWRtaW5caW5zdGl0dXRpb25fYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJETMcnCgSPn22KBBa4Lfhk4p2/IHZloOywcYCu/DFViNz3KEecT/tyrAUp7dhusqjVw7wAN+zEkyHJLTu3F1ROjUDBOMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMA0GA1UdDgQGBAQBAgMEMA8GA1UdIwQIMAaABAECAwQwDgYGUQMEBQYHAQH/BAExMAoGCCqGSM49BAMDA0gAMEUCID8ckZVfn5TlN2Omt8LPdUcb1luw+T93rkOBmFhr8Cb+AiEArmVMqTda8B/ueCEOoKrCbW8qQGGP+K8Q71Tth54J0tk=",
  "signature": "MEYCIQCkgjmWLAylgDAmWOP3Y5Ab9IFSn/E5N30oyctBnupsyAIhAL4tqCtjMrSb3EALSWC3QDNzJxMfGFINd/hK8U6CaUUg"
}`
)

func init() {
	format := logging.MustStringFormatter(`[%{module}] %{time:2006-01-02 15:04:05} [%{level}] [%{longpkg} %{shortfile}] { %{message} }`)

	backendConsole := logging.NewLogBackend(os.Stderr, "", 0)
	backendConsole2Formatter := logging.NewBackendFormatter(backendConsole, format)

	logging.SetBackend(backendConsole2Formatter)
}

func TestProcess(t *testing.T) {

	primitives.InitSecurityLevel("SHA3", 256)

	block, _ := pem.Decode([]byte(chainKey))
	if block == nil {
		logger.Fatal("pem.Decode return nil")
	}

	sk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		logger.Fatal(err)
	}

	tx := &pb.Transaction{}

	if err := json.Unmarshal([]byte(transaction), tx); err != nil {
		logger.Fatal(err)
	}

	if err := Process(tx, sk); err != nil {
		logger.Fatal(err)
	}

	logger.Info("ChaincodeID", string(tx.ChaincodeID))
	logger.Info("Payload", string(tx.Payload))
	logger.Info("Metadata", string(tx.Metadata))
}
