package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/tv42/base58"
)

var (
	Roles  = make(map[string]int) // role : level
	RootCA []byte
)

type Subject struct {
	Country            string
	Organization       string
	OrganizationalUnit string
	Locality           string
	Province           string
	StreetAddress      string
	PostalCode         string
	CommonName         string
	Role               string
}

// ECDSASignature represents an ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

type ECDSAPK struct {
	X, Y *big.Int
}

func String2Identifier(field string) []int {
	var identifier []int
	identifier = append(identifier, 0)
	identifier = append(identifier, 0)
	for _, v := range field[:] {
		identifier = append(identifier, int(v))
	}
	return identifier
}

func Identifier2String(identifier []int) (string, error) {
	buffer := bytes.NewBufferString("")
	var err error
	for i, v := range identifier {
		if i < 2 {
			continue
		}
		if err = buffer.WriteByte(byte(v)); err != nil {
			return "", err
		}
	}
	return buffer.String(), nil
}

func AesEncrypt(key, plain []byte) ([]byte, error) {

	if len(key) < 32 {
		for {
			if len(key) == 32 {
				break
			}
			key = append(key, '0')
		}
	} else if len(key) > 32 {
		key = key[:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	text := make([]byte, aes.BlockSize+len(plain))
	iv := text[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(text[aes.BlockSize:], plain)

	return text, nil
}

func AesDecrypt(key, text []byte) ([]byte, error) {

	if len(key) < 32 {
		for {
			if len(key) == 32 {
				break
			}
			key = append(key, '0')
		}
	} else if len(key) > 32 {
		key = key[:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(text) < aes.BlockSize {
		return nil, errors.New("cipher text too short")
	}

	cfb := cipher.NewCFBDecrypter(block, text[:aes.BlockSize])
	plain := make([]byte, len(text)-aes.BlockSize)
	cfb.XORKeyStream(plain, text[aes.BlockSize:])

	return plain, nil
}

func GenerateUUID() (string, error) {
	uuid := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, uuid)
	if err != nil {
		return "", err
	}

	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80

	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40

	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func LoadCA(privPath, crtPath string, pwd []byte) (*ecdsa.PrivateKey, *x509.Certificate, error) {

	if _, err := os.Stat(crtPath); err != nil {
		return nil, nil, err
	}
	if _, err := os.Stat(privPath); err != nil {
		return nil, nil, err
	}

	crtRaw, err := ioutil.ReadFile(crtPath)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(crtRaw)
	if block == nil {
		return nil, nil, errors.New("pem.Decode return nil")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	privRaw, err := ioutil.ReadFile(privPath)
	if err != nil {
		return nil, nil, err
	}

	block, _ = pem.Decode(privRaw)
	if block == nil {
		return nil, nil, errors.New("pem.Decode return nil")
	}

	var keyRaw []byte

	if pwd == nil {
		keyRaw = block.Bytes
	} else {
		keyRaw, err = x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, nil, err
		}
	}

	priv, err := x509.ParseECPrivateKey(keyRaw)
	if err != nil {
		return nil, nil, err
	}

	return priv, crt, nil
}

func MarshalSerialNumber(num *big.Int) string {
	return num.Text(32)
}

func LoadCARaw(privPath, crtPath string, pwd []byte) ([]byte, []byte, error) {

	if _, err := os.Stat(crtPath); err != nil {
		return nil, nil, err
	}
	if _, err := os.Stat(privPath); err != nil {
		return nil, nil, err
	}

	crtRaw, err := ioutil.ReadFile(crtPath)
	if err != nil {
		return nil, nil, err
	}

	privRaw, err := ioutil.ReadFile(privPath)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(privRaw)
	if block == nil {
		return nil, nil, errors.New("pem.Decode return nil")
	}

	var keyRaw []byte

	if pwd == nil {
		keyRaw = block.Bytes
	} else {
		keyRaw, err = x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, nil, err
		}
	}
	block = &pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw}

	return pem.EncodeToMemory(block), crtRaw, nil
}

func EcdsaSign(sk *ecdsa.PrivateKey, payload []byte) (string, error) {

	hash := sha256.New()
	if _, err := hash.Write(payload); err != nil {
		return "", err
	}

	r, s, err := ecdsa.Sign(rand.Reader, sk, hash.Sum(nil))
	if err != nil {
		return "", err
	}

	raw, err := asn1.Marshal(ECDSASignature{r, s})
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}

func EcdsaVerify(pk *ecdsa.PublicKey, payload []byte, signature string) (bool, error) {

	hash := sha256.New()
	if _, err := hash.Write(payload); err != nil {
		return false, err
	}
	hashed := hash.Sum(nil)

	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	sig := new(ECDSASignature)
	if _, err = asn1.Unmarshal(raw, sig); err != nil {
		return false, err
	}

	return ecdsa.Verify(pk, hashed, sig.R, sig.S), nil
}

func ParshPK(pkRaw string) (*ecdsa.PublicKey, error) {

	block, _ := pem.Decode([]byte(pkRaw))
	if block == nil {
		err := errors.New("pem.Decode return nil")
		return nil, err
	}

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pk.(*ecdsa.PublicKey), nil
}

func ParshSK(skRaw string) (*ecdsa.PrivateKey, error) {

	block, _ := pem.Decode([]byte(skRaw))
	if block == nil {
		err := errors.New("pem.Decode return nil")
		return nil, err
	}

	sk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return sk, nil
}

func GenerateAddress(pk string /*in PEM*/) (string, error) {

	pubK, err := ParshPK(pk)
	if err != nil {
		return "", err
	}

	return GetAddress(pubK)
}

func GetAddress(pk *ecdsa.PublicKey) (string, error) {

	tmp, err := asn1.Marshal(ECDSAPK{pk.X, pk.Y})
	if err != nil {
		return "", err
	}

	loop := 100 * 10000 // for security
	for i := 0; i < loop; i++ {
		hash := sha256.New()
		if _, err := hash.Write(tmp); err != nil {
			return "", err
		}
		tmp = hash.Sum(nil)
	}
	address := base58.EncodeBig(nil, big.NewInt(0).SetBytes(tmp))
	if len(address) == 43 { // in sha256, base58 is 43 or 44
		address = append([]byte{'7', 'x'}, address...)
	} else {
		address = append([]byte{'7'}, address...)
	}
	return string(address), nil
}

func MarshalPK(pub interface{}) (string, error) {

	raw, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	pk := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}))

	return pk, nil
}
