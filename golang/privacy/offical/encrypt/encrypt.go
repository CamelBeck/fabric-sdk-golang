package encrypt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"

	"github.com/hyperledger/fabric/core/crypto/primitives"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/sdk/golang/ecies"
	"github.com/op/go-logging"
)

var (
	logger = logging.MustGetLogger("offical encrypt")
)

type chainCodeValidatorMessage1_2 struct {
	PrivateKey []byte
	StateKey   []byte
}

func Process(tx *pb.Transaction, pk *ecdsa.PublicKey) error {

	priv, err := ecdsa.GenerateKey(primitives.GetDefaultCurve(), rand.Reader)
	if err != nil {
		logger.Error(err)
		return err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		logger.Error(err)
		return err
	}

	var stateKey []byte
	switch tx.Type {
	case pb.Transaction_CHAINCODE_DEPLOY:
		// Prepare chaincode stateKey and privateKey
		stateKey, err = primitives.GenAESKey()
		if err != nil {
			logger.Error(err)
			return err
		}
	case pb.Transaction_CHAINCODE_QUERY:
		// Prepare chaincode stateKey and privateKey
		stateKey = primitives.HMACAESTruncated(nil, append([]byte{6}, tx.Nonce...))
	case pb.Transaction_CHAINCODE_INVOKE:
		// Prepare chaincode stateKey and privateKey
		stateKey = make([]byte, 0)
	}

	msgToValidators, err := asn1.Marshal(chainCodeValidatorMessage1_2{privBytes, stateKey})
	if err != nil {
		logger.Error(err)
		return err
	}

	encMsgToValidators, err := ecies.Encrypt(rand.Reader, pk, msgToValidators)
	if err != nil {
		logger.Error(err)
		return err
	}
	tx.ToValidators = encMsgToValidators

	encryptedChaincodeID, err := ecies.Encrypt(rand.Reader, &priv.PublicKey, tx.ChaincodeID)
	if err != nil {
		logger.Error(err)
		return err
	}
	tx.ChaincodeID = encryptedChaincodeID

	encryptedPayload, err := ecies.Encrypt(rand.Reader, &priv.PublicKey, tx.Payload)
	if err != nil {
		logger.Error(err)
		return err
	}
	tx.Payload = encryptedPayload

	if len(tx.Metadata) != 0 {
		encryptedMetadata, err := ecies.Encrypt(rand.Reader, &priv.PublicKey, tx.Metadata)
		if err != nil {
			logger.Error(err)
			return err
		}
		tx.Metadata = encryptedMetadata
	}

	return nil
}
