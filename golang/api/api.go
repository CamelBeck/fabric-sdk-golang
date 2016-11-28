package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	google_protobuf "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric/core/container"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/crypto/primitives/ecies"
	"github.com/hyperledger/fabric/core/util"
	mem "github.com/hyperledger/fabric/membersrvc/protos"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/sdk/golang/privacy/offical/decrypt"
	"github.com/hyperledger/fabric/sdk/golang/privacy/offical/encrypt"
	eu "github.com/hyperledger/fabric/sdk/golang/util"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	logger = logging.MustGetLogger("api")

	tlsConfig *tls.Config

	// ECertSubjectRole is the ASN1 object identifier of the subject's role.
	ECertSubjectRole = asn1.ObjectIdentifier{2, 1, 3, 4, 5, 6, 7}

	// TCertEncEnrollmentID is the ASN1 object identifier of the enrollment id.
	TCertEncEnrollmentID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 8}

	// Padding for encryption.
	Padding = []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}

	ecaChainCert, tcaChainCert []byte
)

func Init() {

	if viper.GetBool("proxy.tls.enable") {
		pool := x509.NewCertPool()

		caRaw, err := ioutil.ReadFile(viper.GetString("proxy.tls.ca"))
		if err != nil {
			logger.Fatal(err)
		}

		pool.AppendCertsFromPEM(caRaw)

		tlsConfig = &tls.Config{
			RootCAs: pool,
		}

		if viper.GetBool("proxy.tls.verifyClientCert") {
			privRaw, crtRaw, err := eu.LoadCARaw(viper.GetString("proxy.tls.priv"), viper.GetString("proxy.tls.crt"), nil)
			if err != nil {
				logger.Fatal(err)
			}

			cert, err := tls.X509KeyPair(crtRaw, privRaw)
			if err != nil {
				logger.Fatal(err)
			}

			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	_ecaChainCert, _tcaChainCert, err := GetChainCert()
	if err != nil {
		logger.Fatal(err)
	}

	ecaChainCert, tcaChainCert = []byte(_ecaChainCert), []byte(_tcaChainCert)
}

func GetEcaChainCert() []byte {
	return ecaChainCert
}

func GetTcaChainCert() []byte {
	return tcaChainCert
}

// register new user
func Register(req *mem.RegisterUserReq, registarSK *ecdsa.PrivateKey) (string, error) {
	logger.Info("register")

	//sign the req
	hash := primitives.NewHash()
	raw, _ := proto.Marshal(req)
	hash.Write(raw)

	r, s, err := ecdsa.Sign(rand.Reader, registarSK, hash.Sum(nil))
	if err != nil {
		logger.Error(err)
		return "", err
	}
	R, _ := r.MarshalText()
	S, _ := s.MarshalText()
	req.Sig = &mem.Signature{Type: mem.CryptoType_ECDSA, R: R, S: S}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	if viper.GetBool("proxy.tls.enable") {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(viper.GetString("proxy.address"), opts...)
	if err != nil {
		logger.Error("register", "grpc.Dial", err)
		return "", err
	}
	defer conn.Close()

	ecaA := mem.NewECAAClient(conn)
	token, err := ecaA.RegisterUser(context.Background(), req)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	logger.Info("token", string(token.Tok))
	return string(token.Tok), nil
}

// get root ca of eca tca
func GetChainCert() (string, string, error) {
	logger.Info("getChainCert")

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	if viper.GetBool("proxy.tls.enable") {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(viper.GetString("proxy.address"), opts...)
	if err != nil {
		logger.Error("getChainCert", "grpc.Dial", err)
		return "", "", err
	}
	defer conn.Close()

	ecaP := mem.NewECAPClient(conn)
	ecaChainCertRaw, err := ecaP.ReadCACertificate(context.Background(), &mem.Empty{})
	if err != nil {
		logger.Error(err)
		return "", "", err
	}
	ecaChainCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecaChainCertRaw.Cert}))

	tcaP := mem.NewTCAPClient(conn)
	tcaChainCertRaw, err := tcaP.ReadCACertificate(context.Background(), &mem.Empty{})
	if err != nil {
		logger.Error(err)
		return "", "", err
	}
	tcaChainCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tcaChainCertRaw.Cert}))

	logger.Info("ecaChainCert\n", ecaChainCert)
	logger.Info("tcaChainCert\n", tcaChainCert)

	return ecaChainCert, tcaChainCert, nil
}

// get e-cert and tls-cert
func GetEnrollmentData(id, pw string, ecaChainCertRaw []byte) (enrollPriv, enrollCert, chainKey, tlsPriv, tlsCert string, e error) {
	logger.Info("getEnrollmentData")

	block, _ := pem.Decode(ecaChainCertRaw)
	if block == nil {
		e = errors.New("pem.Decode return nil")
		logger.Error(e)
		return
	}

	ecaChainCert, err := x509.ParseCertificate(block.Bytes)
	if e = err; err != nil {
		logger.Error(err)
		return
	}

	ecaCertPool := x509.NewCertPool()
	ecaCertPool.AddCert(ecaChainCert)

	epriv, ecertRaw, chainKeyPem, err := getEnrollmentCertificateFromECA(id, pw, ecaCertPool)
	if e = err; err != nil {
		logger.Error(err)
		return
	}

	eprivRaw, err := x509.MarshalECPrivateKey(epriv)
	if e = err; err != nil {
		logger.Error(err)
		return
	}

	block = &pem.Block{Type: "PRIVATE KEY", Bytes: eprivRaw}
	enrollPriv = string(pem.EncodeToMemory(block))

	enrollCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecertRaw}))

	chainKeyPub, err := primitives.PEMtoPublicKey(chainKeyPem, nil)
	if e = err; err != nil {
		logger.Error(err)
		return
	}
	chainKeyRaw, err := primitives.PublicKeyToPEM(chainKeyPub, nil)
	if e = err; err != nil {
		logger.Error(err)
		return
	}
	chainKey = string(chainKeyRaw)

	tlspriv, tlscertRaw, err := getTLSCertificateFromTLSCA(id, pw)
	if e = err; err != nil {
		logger.Error(err)
		return
	}

	tlsprivRaw, err := x509.MarshalECPrivateKey(tlspriv)
	if e = err; err != nil {
		logger.Error(err)
		return
	}

	block = &pem.Block{Type: "PRIVATE KEY", Bytes: tlsprivRaw}
	tlsPriv = string(pem.EncodeToMemory(block))

	tlsCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlscertRaw}))

	logger.Info("enrollPriv\n", enrollPriv)
	logger.Info("enrollCert\n", enrollCert)
	logger.Info("chainKey\n", chainKey)
	logger.Info("tlsPriv\n", tlsPriv)
	logger.Info("tlsCert\n", tlsCert)

	return
}

// get e-cert
// copy from core/crypto/node_eca.go #(node *nodeImpl) getEnrollmentCertificateFromECA(id, pw string) (interface{}, []byte, []byte, error)
func getEnrollmentCertificateFromECA(id, pw string, ecaCertPool *x509.CertPool) (*ecdsa.PrivateKey, []byte, []byte, error) {

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	if viper.GetBool("proxy.tls.enable") {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(viper.GetString("proxy.address"), opts...)
	if err != nil {
		logger.Error("getEnrollmentCertificateFromECA", "grpc.Dial", err)
		return nil, nil, nil, err
	}
	defer conn.Close()

	ecaP := mem.NewECAPClient(conn)

	signPriv, err := primitives.NewECDSAKey()
	if err != nil {
		logger.Errorf("Failed generating ECDSA key [%s].", err.Error())
		return nil, nil, nil, err
	}
	signPub, err := x509.MarshalPKIXPublicKey(&signPriv.PublicKey)
	if err != nil {
		logger.Errorf("Failed mashalling ECDSA key [%s].", err.Error())
		return nil, nil, nil, err
	}

	encPriv, err := primitives.NewECDSAKey()
	if err != nil {
		logger.Errorf("Failed generating Encryption key [%s].", err.Error())
		return nil, nil, nil, err
	}
	encPub, err := x509.MarshalPKIXPublicKey(&encPriv.PublicKey)
	if err != nil {
		logger.Errorf("Failed marshalling Encryption key [%s].", err.Error())
		return nil, nil, nil, err
	}

	req := &mem.ECertCreateReq{
		Ts:   &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
		Id:   &mem.Identity{Id: id},
		Tok:  &mem.Token{Tok: []byte(pw)},
		Sign: &mem.PublicKey{Type: mem.CryptoType_ECDSA, Key: signPub},
		Enc:  &mem.PublicKey{Type: mem.CryptoType_ECDSA, Key: encPub},
		Sig:  nil}

	resp, err := ecaP.CreateCertificatePair(context.Background(), req)
	if err != nil {
		logger.Errorf("Failed invoking CreateCertficatePair [%s].", err.Error())
		return nil, nil, nil, err
	}

	if resp.FetchResult != nil && resp.FetchResult.Status != mem.FetchAttrsResult_SUCCESS {
		logger.Warning(resp.FetchResult.Msg)
	}
	//out, err := rsa.DecryptPKCS1v15(rand.Reader, encPriv, resp.Tok.Tok)
	spi := ecies.NewSPI()
	eciesKey, err := spi.NewPrivateKey(nil, encPriv)
	if err != nil {
		logger.Errorf("Failed parsing decrypting key [%s].", err.Error())
		return nil, nil, nil, err
	}

	ecies, err := spi.NewAsymmetricCipherFromPublicKey(eciesKey)
	if err != nil {
		logger.Errorf("Failed creating asymmetrinc cipher [%s].", err.Error())
		return nil, nil, nil, err
	}

	out, err := ecies.Process(resp.Tok.Tok)
	if err != nil {
		logger.Errorf("Failed decrypting toke [%s].", err.Error())
		return nil, nil, nil, err
	}

	req.Tok.Tok = out
	req.Sig = nil

	hash := primitives.NewHash()
	raw, _ := proto.Marshal(req)
	hash.Write(raw)

	r, s, err := ecdsa.Sign(rand.Reader, signPriv, hash.Sum(nil))
	if err != nil {
		logger.Errorf("Failed signing [%s].", err.Error())
		return nil, nil, nil, err
	}
	R, _ := r.MarshalText()
	S, _ := s.MarshalText()
	req.Sig = &mem.Signature{Type: mem.CryptoType_ECDSA, R: R, S: S}

	resp, err = ecaP.CreateCertificatePair(context.Background(), req)
	if err != nil {
		logger.Errorf("Failed invoking CreateCertificatePair [%s].", err.Error())
		return nil, nil, nil, err
	}

	// Verify response

	// Verify cert for signing
	logger.Debugf("Enrollment certificate for signing [% x]", primitives.Hash(resp.Certs.Sign))

	x509SignCert, err := primitives.DERToX509Certificate(resp.Certs.Sign)
	if err != nil {
		logger.Errorf("Failed parsing signing enrollment certificate for signing: [%s]", err)
		return nil, nil, nil, err
	}

	_, err = primitives.GetCriticalExtension(x509SignCert, ECertSubjectRole)
	if err != nil {
		logger.Errorf("Failed parsing ECertSubjectRole in enrollment certificate for signing: [%s]", err)
		return nil, nil, nil, err
	}

	err = primitives.CheckCertAgainstSKAndRoot(x509SignCert, signPriv, ecaCertPool)
	if err != nil {
		logger.Errorf("Failed checking signing enrollment certificate for signing: [%s]", err)
		return nil, nil, nil, err
	}

	// Verify cert for encrypting
	logger.Debugf("Enrollment certificate for encrypting [% x]", primitives.Hash(resp.Certs.Enc))

	x509EncCert, err := primitives.DERToX509Certificate(resp.Certs.Enc)
	if err != nil {
		logger.Errorf("Failed parsing signing enrollment certificate for encrypting: [%s]", err)
		return nil, nil, nil, err
	}

	_, err = primitives.GetCriticalExtension(x509EncCert, ECertSubjectRole)
	if err != nil {
		logger.Errorf("Failed parsing ECertSubjectRole in enrollment certificate for encrypting: [%s]", err)
		return nil, nil, nil, err
	}

	err = primitives.CheckCertAgainstSKAndRoot(x509EncCert, encPriv, ecaCertPool)
	if err != nil {
		logger.Errorf("Failed checking signing enrollment certificate for encrypting: [%s]", err)
		return nil, nil, nil, err
	}

	return signPriv, resp.Certs.Sign, resp.Pkchain, nil
}

// get tls-cert
// copy from core/crypto/node_tlsca.go #func (node *nodeImpl) getTLSCertificateFromTLSCA(id, affiliation string) (interface{}, []byte, error)
func getTLSCertificateFromTLSCA(id, affiliation string) (*ecdsa.PrivateKey, []byte, error) {

	var opts []grpc.DialOption
	if viper.GetBool("proxy.tls.enable") {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(viper.GetString("proxy.address"), opts...)
	if err != nil {
		logger.Error("getTLSCertificateFromTLSCA", "grpc.Dial", err)
		return nil, nil, err
	}
	defer conn.Close()

	tlscaP := mem.NewTLSCAPClient(conn)

	priv, err := primitives.NewECDSAKey()

	if err != nil {
		logger.Errorf("Failed generating key: %s", err)
		return nil, nil, err
	}

	uuid := util.GenerateUUID()

	// Prepare the request
	pubraw, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	now := time.Now()
	timestamp := google_protobuf.Timestamp{Seconds: int64(now.Second()), Nanos: int32(now.Nanosecond())}

	req := &mem.TLSCertCreateReq{
		Ts: &timestamp,
		Id: &mem.Identity{Id: id + "-" + uuid},
		Pub: &mem.PublicKey{
			Type: mem.CryptoType_ECDSA,
			Key:  pubraw,
		}, Sig: nil}
	rawreq, _ := proto.Marshal(req)
	r, s, err := ecdsa.Sign(rand.Reader, priv, primitives.Hash(rawreq))
	if err != nil {
		logger.Errorf("Failed ecdsa.Sign: %s", err)
		return nil, nil, err
	}
	R, _ := r.MarshalText()
	S, _ := s.MarshalText()
	req.Sig = &mem.Signature{Type: mem.CryptoType_ECDSA, R: R, S: S}

	resp, err := tlscaP.CreateCertificate(context.Background(), req)
	if err != nil {
		logger.Errorf("Failed requesting tls certificate: %s", err)
		return nil, nil, err
	}

	tlsCert, err := primitives.DERToX509Certificate(resp.Cert.Cert)
	certPK := tlsCert.PublicKey.(*ecdsa.PublicKey)
	primitives.VerifySignCapability(priv, certPK)

	return priv, resp.Cert.Cert, nil
}

// copy from core/crypto/client_tca.go #func (client *clientImpl) getTCertsFromTCA(attrhash string, attributes []string, num int) error
func GetTCertsFromTCA(enrollID string, enrollPriv *ecdsa.PrivateKey, attributes []string, num int, tcaChainCertRaw []byte) (kdfKey string, tCerts []map[string]string, e error) {
	logger.Infof("...Get [%d] certificates from the TCA...", num)

	block, _ := pem.Decode(tcaChainCertRaw)
	if block == nil {
		e = errors.New("pem.Decode return nil")
		logger.Error(e)
		return
	}

	tcaChainCert, err := x509.ParseCertificate(block.Bytes)
	if e = err; err != nil {
		logger.Error(err)
		return
	}

	tcaCertPool := x509.NewCertPool()
	tcaCertPool.AddCert(tcaChainCert)

	// Contact the TCA
	TCertOwnerKDFKey, certDERs, err := callTCACreateCertificateSet(enrollID, enrollPriv, attributes, num)
	if e = err; err != nil {
		logger.Errorf("Failed contacting TCA [%s].", err.Error())
		return
	}

	kdfKeyRaw, err := primitives.AEStoEncryptedPEM(TCertOwnerKDFKey, nil)
	if e = err; err != nil {
		logger.Error("Failed converting key to PEM", err)
		return
	}

	kdfKey = string(kdfKeyRaw)
	logger.Info("kdfKey\n", kdfKey)

	// Validate the Certificates obtained

	TCertOwnerEncryptKey := primitives.HMACAESTruncated(TCertOwnerKDFKey, []byte{1})
	ExpansionKey := primitives.HMAC(TCertOwnerKDFKey, []byte{2})

	j := 0
	for i := 0; i < num; i++ {
		// DER to x509
		x509Cert, err := primitives.DERToX509Certificate(certDERs[i].Cert)
		prek0 := certDERs[i].Prek0
		if err != nil {
			logger.Errorf("Failed parsing certificate [% x]: [%s].", certDERs[i].Cert, err)
			continue
		}

		// Handle Critical Extenstion TCertEncTCertIndex
		tCertIndexCT, err := primitives.GetCriticalExtension(x509Cert, primitives.TCertEncTCertIndex)
		if err != nil {
			logger.Errorf("Failed getting extension TCERT_ENC_TCERTINDEX [% x]: [%s].", primitives.TCertEncTCertIndex, err)
			continue
		}

		// Verify certificate against root
		if _, err := primitives.CheckCertAgainRoot(x509Cert, tcaCertPool); err != nil {
			logger.Warningf("Warning verifing certificate [%s].", err.Error())
			continue
		}

		// Verify public key

		// 384-bit ExpansionValue = HMAC(Expansion_Key, TCertIndex)
		// Let TCertIndex = Timestamp, RandValue, 1,2,…
		// Timestamp assigned, RandValue assigned and counter reinitialized to 1 per batch

		// Decrypt ct to TCertIndex (TODO: || EnrollPub_Key || EnrollID ?)
		pt, err := primitives.CBCPKCS7Decrypt(TCertOwnerEncryptKey, tCertIndexCT)
		if err != nil {
			logger.Errorf("Failed decrypting extension TCERT_ENC_TCERTINDEX [%s].", err.Error())
			continue
		}

		// Compute ExpansionValue based on TCertIndex
		TCertIndex := pt
		//		TCertIndex := []byte(strconv.Itoa(i))

		logger.Debugf("TCertIndex: [% x].", TCertIndex)
		mac := hmac.New(primitives.NewHash, ExpansionKey)
		mac.Write(TCertIndex)
		ExpansionValue := mac.Sum(nil)

		// Derive tpk and tsk accordingly to ExpansionValue from enrollment pk,sk
		// Computable by TCA / Auditor: TCertPub_Key = EnrollPub_Key + ExpansionValue G
		// using elliptic curve point addition per NIST FIPS PUB 186-4- specified P-384

		// Compute temporary secret key
		tempSK := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: enrollPriv.Curve,
				X:     new(big.Int),
				Y:     new(big.Int),
			},
			D: new(big.Int),
		}

		var k = new(big.Int).SetBytes(ExpansionValue)
		var one = new(big.Int).SetInt64(1)
		n := new(big.Int).Sub(enrollPriv.Params().N, one)
		k.Mod(k, n)
		k.Add(k, one)

		tempSK.D.Add(enrollPriv.D, k)
		tempSK.D.Mod(tempSK.D, enrollPriv.PublicKey.Params().N)

		// Compute temporary public key
		tempX, tempY := enrollPriv.PublicKey.ScalarBaseMult(k.Bytes())
		tempSK.PublicKey.X, tempSK.PublicKey.Y =
			tempSK.PublicKey.Add(
				enrollPriv.PublicKey.X, enrollPriv.PublicKey.Y,
				tempX, tempY,
			)

		// Verify temporary public key is a valid point on the reference curve
		isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
		if !isOn {
			logger.Error("Failed temporary public key IsOnCurve check.")
			continue
		}

		// Check that the derived public key is the same as the one in the certificate
		certPK := x509Cert.PublicKey.(*ecdsa.PublicKey)

		if certPK.X.Cmp(tempSK.PublicKey.X) != 0 {
			logger.Error("Derived public key is different on X")
			continue
		}

		if certPK.Y.Cmp(tempSK.PublicKey.Y) != 0 {
			logger.Error("Derived public key is different on Y")
			continue
		}

		// Verify the signing capability of tempSK
		err = primitives.VerifySignCapability(tempSK, x509Cert.PublicKey)
		if err != nil {
			logger.Errorf("Failed verifing signing capability [%s].", err.Error())
			continue
		}

		// Marshall certificate and secret key to be stored in the database
		if err != nil {
			logger.Errorf("Failed marshalling private key [%s].", err.Error())
			continue
		}

		if err := primitives.CheckCertPKAgainstSK(x509Cert, interface{}(tempSK)); err != nil {
			logger.Errorf("Failed checking TCA cert PK against private key [%s].", err.Error())
			continue
		}

		logger.Debugf("Sub index [%d]", j)
		j++
		logger.Debugf("Certificate [%d] validated.", i)

		prek0Cp := make([]byte, len(prek0))
		copy(prek0Cp, prek0)

		/*
			x509Cert // *x509.Certificate
			tempSK   // *ecdsa.PrivateKey
			prek0Cp  // []byte
		*/

		keyRaw, err := x509.MarshalECPrivateKey(tempSK)
		if e = err; err != nil {
			logger.Error(err)
			return
		}
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw}
		sk := string(pem.EncodeToMemory(block))
		cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509Cert.Raw}))

		tCert := make(map[string]string)
		tCert["cert"] = cert
		tCert["sk"] = sk
		tCert["preK0"] = hex.EncodeToString(prek0Cp)

		enroll, err := getEnrollmentFromTcert(x509Cert.Raw, prek0Cp)
		if e = err; err != nil {
			logger.Error(err)
			return
		}
		tCert["enroll"] = enroll

		tCerts = append(tCerts, tCert)
	}

	if j == 0 {
		e = errors.New("No valid TCert was sent.")
		logger.Error(e)
		return
	}

	logger.Info(tCerts)
	return
}

// call mem create t-certs
// copy from core/crypto/client_tca.go #func (client *clientImpl) callTCACreateCertificateSet(num int, attributes []string) ([]byte, []*membersrvc.TCert, error)
func callTCACreateCertificateSet(enrollID string, enrollPriv *ecdsa.PrivateKey, attributes []string, num int) ([]byte, []*mem.TCert, error) {

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	if viper.GetBool("proxy.tls.enable") {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(viper.GetString("proxy.address"), opts...)
	if err != nil {
		logger.Error("callTCACreateCertificateSet", "grpc.Dial", err)
		return nil, nil, err
	}
	defer conn.Close()

	tcaP := mem.NewTCAPClient(conn)

	var attributesList []*mem.TCertAttribute

	for _, k := range attributes {
		tcertAttr := new(mem.TCertAttribute)
		tcertAttr.AttributeName = k
		attributesList = append(attributesList, tcertAttr)
	}

	// Execute the protocol
	now := time.Now()
	timestamp := google_protobuf.Timestamp{Seconds: int64(now.Second()), Nanos: int32(now.Nanosecond())}
	req := &mem.TCertCreateSetReq{
		Ts:         &timestamp,
		Id:         &mem.Identity{Id: enrollID},
		Num:        uint32(num),
		Attributes: attributesList,
		Sig:        nil,
	}

	rawReq, err := proto.Marshal(req)
	if err != nil {
		logger.Errorf("Failed marshaling request [%s].", err.Error())
		return nil, nil, err
	}

	// 2. Sign rawReq
	r, s, err := primitives.ECDSASignDirect(enrollPriv, rawReq)

	if err != nil {
		logger.Errorf("Failed creating signature for [% x]: [%s].", rawReq, err.Error())
		return nil, nil, err
	}

	R, _ := r.MarshalText()
	S, _ := s.MarshalText()

	// 3. Append the signature
	req.Sig = &mem.Signature{Type: mem.CryptoType_ECDSA, R: R, S: S}

	// 4. Send request
	certSet, err := tcaP.CreateCertificateSet(context.Background(), req)
	if err != nil {
		logger.Errorf("Failed requesting tca create certificate set [%s].", err.Error())
		return nil, nil, err
	}

	return certSet.Certs.Key, certSet.Certs.Certs, nil
}

func Deploy(path string, args []string, metadata []byte, signKey *ecdsa.PrivateKey, rawCrt []byte, chainPk *ecdsa.PublicKey) (*pb.Response, error) {
	logger.Info("deploy")

	spec := &pb.ChaincodeSpec{
		Type:        pb.ChaincodeSpec_GOLANG,
		ChaincodeID: &pb.ChaincodeID{Path: path},
		CtorMsg:     &pb.ChaincodeInput{util.ToChaincodeArgs(args...)},
	}

	codePackageBytes, err := container.GetChaincodePackageBytes(spec)
	if err != nil {
		logger.Error("Error getting chaincode package bytes", err)
		return nil, err
	}

	deploySpec := &pb.ChaincodeDeploymentSpec{
		ChaincodeSpec: spec,
		CodePackage:   codePackageBytes,
	}

	tx, err := pb.NewChaincodeDeployTransaction(deploySpec, spec.ChaincodeID.Name)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	tx.Metadata = metadata
	tx.Nonce, err = primitives.GetRandomNonce()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if viper.GetBool("security.privacy") {
		tx.ConfidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
		tx.ConfidentialityProtocolVersion = viper.GetString("security.confidentialityProtocolVersion")
		if err = encrypt.Process(tx, chainPk); err != nil {
			logger.Error(err)
			return nil, err
		}
	}

	tx.Cert = rawCrt

	rawTx, err := proto.Marshal(tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	rawSignature, err := primitives.ECDSASign(signKey, rawTx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	tx.Signature = rawSignature

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	if viper.GetBool("proxy.tls.enable") {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(viper.GetString("proxy.address"), opts...)
	if err != nil {
		logger.Error("deploy", "grpc.Dial", err)
		return nil, err
	}
	defer conn.Close()
	peer := pb.NewPeerClient(conn)

	resp, err := peer.ProcessTransaction(context.Background(), tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	logger.Info("deploy resp", resp)
	return resp, nil
}

func Invoke(name string, args []string, txid string, metadata []byte, signKey *ecdsa.PrivateKey, rawCrt []byte, chainPk *ecdsa.PublicKey) (*pb.Response, error) {
	logger.Info("invoke")

	spec := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			Type:        pb.ChaincodeSpec_GOLANG,
			ChaincodeID: &pb.ChaincodeID{Name: name},
			CtorMsg:     &pb.ChaincodeInput{util.ToChaincodeArgs(args...)},
		},
	}

	tx, err := pb.NewChaincodeExecute(spec, txid, pb.Transaction_CHAINCODE_INVOKE)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	tx.Metadata = metadata
	tx.Nonce, err = primitives.GetRandomNonce()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if viper.GetBool("security.privacy") {
		tx.ConfidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
		tx.ConfidentialityProtocolVersion = viper.GetString("security.confidentialityProtocolVersion")
		if err = encrypt.Process(tx, chainPk); err != nil {
			logger.Error(err)
			return nil, err
		}
	}
	tx.Cert = rawCrt

	rawTx, err := proto.Marshal(tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	rawSignature, err := primitives.ECDSASign(signKey, rawTx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	tx.Signature = rawSignature

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	if viper.GetBool("proxy.tls.enable") {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(viper.GetString("proxy.address"), opts...)
	if err != nil {
		logger.Error("invoke", "grpc.Dial", err)
		return nil, err
	}
	defer conn.Close()
	peer := pb.NewPeerClient(conn)

	resp, err := peer.ProcessTransaction(context.Background(), tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	logger.Info("invoke resp", resp)
	return resp, nil
}

func Query(name string, args []string, txid string, metadata []byte, signKey *ecdsa.PrivateKey, rawCrt []byte, chainPk *ecdsa.PublicKey) (*pb.Response, error) {
	logger.Info("query")

	spec := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			Type:        pb.ChaincodeSpec_GOLANG,
			ChaincodeID: &pb.ChaincodeID{Name: name},
			CtorMsg:     &pb.ChaincodeInput{util.ToChaincodeArgs(args...)},
		},
	}

	tx, err := pb.NewChaincodeExecute(spec, txid, pb.Transaction_CHAINCODE_QUERY)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	tx.Metadata = metadata
	tx.Nonce, err = primitives.GetRandomNonce()
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if viper.GetBool("security.privacy") {
		tx.ConfidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
		tx.ConfidentialityProtocolVersion = viper.GetString("security.confidentialityProtocolVersion")
		if err = encrypt.Process(tx, chainPk); err != nil {
			logger.Error(err)
			return nil, err
		}
	}
	tx.Cert = rawCrt

	rawTx, err := proto.Marshal(tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	rawSignature, err := primitives.ECDSASign(signKey, rawTx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	tx.Signature = rawSignature

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTimeout(time.Second*3))
	if viper.GetBool("proxy.tls.enable") {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(viper.GetString("proxy.address"), opts...)
	if err != nil {
		logger.Error("query", "grpc.Dial", err)
		return nil, err
	}
	defer conn.Close()
	peer := pb.NewPeerClient(conn)

	resp, err := peer.ProcessTransaction(context.Background(), tx)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if viper.GetBool("security.privacy") {
		if resp.Status == pb.Response_FAILURE {
			logger.Error(string(resp.Msg))
			return nil, err
		}

		if resp.Msg, err = decrypt.DecryptQueryResult(tx, resp.Msg); nil != err {
			logger.Errorf("Failed decrypting query transaction result %s", string(resp.Msg[:]))
			return nil, err
		}
	}

	logger.Info("query resp", resp)
	return resp, nil
}

func Chain() (string, error) {

	logger.Info("chain")

	client := &http.Client{}
	var url string
	if viper.GetBool("proxy.tls.enable") {
		client.Transport = &http.Transport{
			TLSClientConfig:    tlsConfig,
			DisableCompression: true,
		}
		url = fmt.Sprint("https://", viper.GetString("proxy.address"), "/chain")
	} else {
		url = fmt.Sprint("http://", viper.GetString("proxy.address"), "/chain")
	}

	resp, err := client.Get(url)
	if err != nil {
		logger.Error(err)
		return "", err
	}
	logger.Info("resp.Status:", resp.Status)
	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	var buf bytes.Buffer
	if err = json.Indent(&buf, msg, "", " "); err != nil {
		logger.Error(err)
		return "", err
	}

	return string(buf.Bytes()), nil
}

func ChainBlocks(block int) (string, error) {

	logger.Info("chainBlocks")

	client := &http.Client{}
	var url string
	if viper.GetBool("proxy.tls.enable") {
		client.Transport = &http.Transport{
			TLSClientConfig:    tlsConfig,
			DisableCompression: true,
		}
		url = fmt.Sprint("https://", viper.GetString("proxy.address"), "/chain/blocks/", strconv.Itoa(block))
	} else {
		url = fmt.Sprint("http://", viper.GetString("proxy.address"), "/chain/blocks/", strconv.Itoa(block))
	}

	resp, err := client.Get(url)
	if err != nil {
		logger.Error(err)
		return "", err
	}
	logger.Info("resp.Status:", resp.Status)
	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	var buf bytes.Buffer
	if err = json.Indent(&buf, msg, "", " "); err != nil {
		logger.Error(err)
		return "", err
	}

	return string(buf.Bytes()), nil
}

func Transactions(txid string) (string, error) {

	logger.Info("transactions")

	client := &http.Client{}
	var url string
	if viper.GetBool("proxy.tls.enable") {
		client.Transport = &http.Transport{
			TLSClientConfig:    tlsConfig,
			DisableCompression: true,
		}
		url = fmt.Sprint("https://", viper.GetString("proxy.address"), "/transactions/", txid)
	} else {
		url = fmt.Sprint("http://", viper.GetString("proxy.address"), "/transactions/", txid)
	}

	resp, err := client.Get(url)
	if err != nil {
		logger.Error(err)
		return "", err
	}
	logger.Info("resp.Status:", resp.Status)
	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	var buf bytes.Buffer
	if err = json.Indent(&buf, msg, "", " "); err != nil {
		logger.Error(err)
		return "", err
	}

	return string(buf.Bytes()), nil
}

func Network() (string, error) {

	logger.Info("network")

	client := &http.Client{}
	var url string
	if viper.GetBool("proxy.tls.enable") {
		client.Transport = &http.Transport{
			TLSClientConfig:    tlsConfig,
			DisableCompression: true,
		}
		url = fmt.Sprint("https://", viper.GetString("proxy.address"), "/network/peers")
	} else {
		url = fmt.Sprint("http://", viper.GetString("proxy.address"), "/network/peers")
	}

	resp, err := client.Get(url)
	if err != nil {
		logger.Error(err)
		return "", err
	}
	logger.Info("resp.Status:", resp.Status)
	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	var buf bytes.Buffer
	if err = json.Indent(&buf, msg, "", " "); err != nil {
		logger.Error(err)
		return "", err
	}

	return string(buf.Bytes()), nil
}

func getEnrollmentFromTcert(certRaw, preK0 []byte) (string, error) {

	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	mac := hmac.New(primitives.GetDefaultHash(), preK0)
	mac.Write([]byte("enrollmentID"))
	enrollmentIDKey := mac.Sum(nil)[:32]

	var encEnrollmentID []byte
	for _, v := range cert.Extensions {
		if v.Id.Equal(TCertEncEnrollmentID) {
			encEnrollmentID = v.Value
			break
		}
	}

	if encEnrollmentID == nil {
		err = errors.New("not found enrollID")
		logger.Error(err)
		return "", err
	}

	enrollmentIDRaw, err := primitives.CBCPKCS7Decrypt(enrollmentIDKey, encEnrollmentID)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	enrollmentID := strings.TrimRight(string(enrollmentIDRaw), string(Padding))

	return enrollmentID, nil
}
