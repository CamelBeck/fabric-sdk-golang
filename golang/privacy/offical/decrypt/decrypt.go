package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/crypto/utils"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/sdk/golang/ecies"
	"github.com/op/go-logging"
)

var (
	logger = logging.MustGetLogger("offical decrypt")
)

type chainCodeValidatorMessage1_2 struct {
	PrivateKey []byte
	StateKey   []byte
}

func Process(tx *pb.Transaction, sk *ecdsa.PrivateKey) error {

	msgToValidatorsRaw, err := ecies.Decrypt(sk, tx.ToValidators)
	if err != nil {
		logger.Error(err)
		return err
	}

	msgToValidators := new(chainCodeValidatorMessage1_2)
	_, err = asn1.Unmarshal(msgToValidatorsRaw, msgToValidators)
	if err != nil {
		logger.Error(err)
		return err
	}

	priv, err := x509.ParseECPrivateKey(msgToValidators.PrivateKey)
	if err != nil {
		logger.Error(err)
		return err
	}

	payload, err := ecies.Decrypt(priv, tx.Payload)
	if err != nil {
		logger.Error(err)
		return err
	}
	tx.Payload = payload

	chaincodeID, err := ecies.Decrypt(priv, tx.ChaincodeID)
	if err != nil {
		logger.Error(err)
		return err
	}
	tx.ChaincodeID = chaincodeID

	if len(tx.Metadata) != 0 {
		metadata, err := ecies.Decrypt(priv, tx.Metadata)
		if err != nil {
			logger.Error(err)
			return err
		}
		tx.Metadata = metadata
	}

	return nil
}

func DecryptQueryResult(queryTx *pb.Transaction, ct []byte) ([]byte, error) {

	var queryKey []byte

	switch queryTx.ConfidentialityProtocolVersion {
	case "1.2":
		queryKey = primitives.HMACAESTruncated(nil, append([]byte{6}, queryTx.Nonce...))
	}

	if len(ct) <= primitives.NonceSize {
		return nil, utils.ErrDecrypt
	}

	c, err := aes.NewCipher(queryKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, ct)

	out, err := gcm.Open(nil, nonce, ct[gcm.NonceSize():], nil)
	if err != nil {
		logger.Errorf("Failed decrypting query result [%s].", err.Error())
		return nil, utils.ErrDecrypt
	}
	return out, nil
}
