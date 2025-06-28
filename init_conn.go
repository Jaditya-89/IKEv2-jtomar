package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net"
	"time"

	"github.com/free5gc/n3iwf/context"
	"github.com/free5gc/n3iwf/ike/handler"
	"github.com/free5gc/n3iwf/ike/message"
	"github.com/matanbroner/UESimulator/src/ue/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var n3iwfContext context.N3IWFContext

type ResponderId struct {
	responderType uint8
	responderData []byte
}

func createIKEChildSecurityAssociation(chosenSecurityAssociation *message.SecurityAssociation, inboundSPI uint32) (*context.ChildSecurityAssociation, error) {
	childSecurityAssociation := new(context.ChildSecurityAssociation)

	if chosenSecurityAssociation == nil {
		return nil, errors.New("chosenSecurityAssociation is nil")
	}

	if len(chosenSecurityAssociation.Proposals) == 0 {
		return nil, errors.New("no proposal")
	}

	childSecurityAssociation.SPI = inboundSPI
	fmt.Println(childSecurityAssociation.SPI)

	if len(chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm) != 0 {
		childSecurityAssociation.EncryptionAlgorithm = chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm) != 0 {
		childSecurityAssociation.IntegrityAlgorithm = chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers) != 0 {
		if chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers[0].TransformID == 0 {
			childSecurityAssociation.ESN = false
		} else {
			childSecurityAssociation.ESN = true
		}
	}

	return childSecurityAssociation, nil
}

func parseIPAddressInformationToChildSecurityAssociation(
	childSecurityAssociation *context.ChildSecurityAssociation,
	localInitData *LocalIkeSaInitData,
	trafficSelectorLocal *message.IndividualTrafficSelector,
	trafficSelectorRemote *message.IndividualTrafficSelector) error {

	if childSecurityAssociation == nil {
		return errors.New("childSecurityAssociation is nil")
	}

	childSecurityAssociation.PeerPublicIPAddr = net.ParseIP(localInitData.remoteIp).To4()
	childSecurityAssociation.LocalPublicIPAddr = net.ParseIP(localInitData.localIp).To4()

	if trafficSelectorLocal == nil || trafficSelectorRemote == nil {
		return nil
	}

	childSecurityAssociation.TrafficSelectorLocal = net.IPNet{
		IP:   trafficSelectorLocal.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	childSecurityAssociation.TrafficSelectorRemote = net.IPNet{
		IP:   trafficSelectorRemote.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	return nil
}

func getKeyLength(transformType uint8, transformID uint16, attributePresent bool,
	attributeValue uint16,
) (int, bool) {
	switch transformType {
	case message.TypeEncryptionAlgorithm:
		switch transformID {
		case message.ENCR_DES_IV64:
			return 0, false
		case message.ENCR_DES:
			return 8, true
		case message.ENCR_3DES:
			return 24, true
		case message.ENCR_RC5:
			return 0, false
		case message.ENCR_IDEA:
			return 0, false
		case message.ENCR_CAST:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 16, true
				case 256:
					return 0, false
				default:
					return 0, false
				}
			}
			return 0, false
		case message.ENCR_BLOWFISH: // Blowfish support variable key length
			if attributePresent {
				if attributeValue < 40 {
					return 0, false
				} else if attributeValue > 448 {
					return 0, false
				} else {
					return int(attributeValue / 8), true
				}
			} else {
				return 0, false
			}
		case message.ENCR_3IDEA:
			return 0, false
		case message.ENCR_DES_IV32:
			return 0, false
		case message.ENCR_NULL:
			return 0, true
		case message.ENCR_AES_CBC:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 16, true
				case 192:
					return 24, true
				case 256:
					return 32, true
				default:
					return 0, false
				}
			} else {
				return 0, false
			}
		case message.ENCR_AES_CTR:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 20, true
				case 192:
					return 28, true
				case 256:
					return 36, true
				default:
					return 0, false
				}
			} else {
				return 0, false
			}
		default:
			return 0, false
		}
	case message.TypePseudorandomFunction:
		switch transformID {
		case message.PRF_HMAC_MD5:
			return 16, true
		case message.PRF_HMAC_SHA1:
			return 20, true
		case message.PRF_HMAC_TIGER:
			return 0, false
		default:
			return 0, false
		}
	case message.TypeIntegrityAlgorithm:
		switch transformID {
		case message.AUTH_NONE:
			return 0, false
		case message.AUTH_HMAC_MD5_96:
			return 16, true
		case message.AUTH_HMAC_SHA1_96:
			return 20, true
		case message.AUTH_DES_MAC:
			return 0, false
		case message.AUTH_KPDK_MD5:
			return 0, false
		case message.AUTH_AES_XCBC_96:
			return 0, false
		default:
			return 0, false
		}
	case message.TypeDiffieHellmanGroup:
		switch transformID {
		case message.DH_NONE:
			return 0, false
		case message.DH_768_BIT_MODP:
			return 0, false
		case message.DH_1024_BIT_MODP:
			return 0, false
		case message.DH_1536_BIT_MODP:
			return 0, false
		case message.DH_2048_BIT_MODP:
			return 0, false
		case message.DH_3072_BIT_MODP:
			return 0, false
		case message.DH_4096_BIT_MODP:
			return 0, false
		case message.DH_6144_BIT_MODP:
			return 0, false
		case message.DH_8192_BIT_MODP:
			return 0, false
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func GenerateKeyForChildSA(ikeSecurityAssociation *context.IKESecurityAssociation,
	childSecurityAssociation *context.ChildSecurityAssociation, isCreateChildSA bool,
	concatenatedNonce []byte,
) error {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return errors.New("IKE SA is nil")
	}
	if childSecurityAssociation == nil {
		return errors.New("Child SA is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.PseudorandomFunction == nil {
		return errors.New("No pseudorandom function specified")
	}
	if ikeSecurityAssociation.IKEAuthResponseSA == nil {
		return errors.New("No IKE_AUTH response SA specified")
	}
	if len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals) == 0 {
		return errors.New("No proposal in IKE_AUTH response SA")
	}
	if len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].EncryptionAlgorithm) == 0 {
		return errors.New("No encryption algorithm specified")
	}

	if len(ikeSecurityAssociation.SK_d) == 0 {
		return errors.New("No key deriving key")
	}

	// Transforms
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction
	transformEncryptionAlgorithmForIPSec := ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].EncryptionAlgorithm[0]
	var transformIntegrityAlgorithmForIPSec *message.Transform
	if len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm) != 0 {
		transformIntegrityAlgorithmForIPSec = ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm[0]
	}

	// Get key length for encryption and integrity key for IPSec
	var lengthEncryptionKeyIPSec, lengthIntegrityKeyIPSec, totalKeyLength int
	var ok bool

	if lengthEncryptionKeyIPSec, ok = getKeyLength(transformEncryptionAlgorithmForIPSec.TransformType,
		transformEncryptionAlgorithmForIPSec.TransformID,
		transformEncryptionAlgorithmForIPSec.AttributePresent,
		transformEncryptionAlgorithmForIPSec.AttributeValue); !ok {
		logger.IKELog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	if transformIntegrityAlgorithmForIPSec != nil {
		if lengthIntegrityKeyIPSec, ok = getKeyLength(transformIntegrityAlgorithmForIPSec.TransformType,
			transformIntegrityAlgorithmForIPSec.TransformID,
			transformIntegrityAlgorithmForIPSec.AttributePresent,
			transformIntegrityAlgorithmForIPSec.AttributeValue); !ok {
			logger.IKELog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
			return errors.New("Get key length failed")
		}
	}
	totalKeyLength = lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec
	totalKeyLength = totalKeyLength * 2
	var seed []byte

	// Generate key for child security association as specified in RFC 7296 section 2.17
	if isCreateChildSA == true {
		seed = concatenatedNonce
	} else {
		seed = ikeSecurityAssociation.ConcatenatedNonce
	}
	var pseudorandomFunction hash.Hash

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok = handler.NewPseudorandomFunction(ikeSecurityAssociation.SK_d,
			transformPseudorandomFunction.TransformID); !ok {
			logger.IKELog.Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			logger.IKELog.Errorf("Pseudorandom function write error: %+v", err)
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	childSecurityAssociation.InitiatorToResponderEncryptionKey = append(
		childSecurityAssociation.InitiatorToResponderEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.InitiatorToResponderIntegrityKey = append(
		childSecurityAssociation.InitiatorToResponderIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)
	keyStream = keyStream[lengthIntegrityKeyIPSec:]
	childSecurityAssociation.ResponderToInitiatorEncryptionKey = append(
		childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.ResponderToInitiatorIntegrityKey = append(
		childSecurityAssociation.ResponderToInitiatorIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)

	return nil
}

func setupUDPSocket(localInitData *LocalIkeSaInitData) (*net.UDPConn, error) {
	lBindAddr := fmt.Sprintf("%s:500", localInitData.localIp)
	lAddr, err := net.ResolveUDPAddr("udp", lBindAddr)
	if err != nil {
		fmt.Println("Resolve addr for lBindAddr failed")
		return nil, err
	}
	rBindAddr := fmt.Sprintf("%s:500", localInitData.remoteIp)
	rAddr, err := net.ResolveUDPAddr("udp", rBindAddr)
	if err != nil {
		fmt.Println("Resolve addr for rBindAddr failed")
		return nil, err
	}
	udpListener, err := net.DialUDP("udp", lAddr, rAddr)
	if err != nil {
		fmt.Println("Dial UDP failed")
		return nil, err
	}
	return udpListener, nil
}

func encryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation, ikePayload message.IKEPayloadContainer, requestIKEMessage *message.IKEMessage) error {
	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength := 12 // HMAC_SHA1_96

	// Encrypting
	notificationPayloadData, err := ikePayload.Encode()
	if err != nil {
		return errors.New("encoding IKE payload failed")
	}

	encryptedData, err := handler.EncryptMessage(ikeSecurityAssociation.SK_ei, notificationPayloadData, transformEncryptionAlgorithm.TransformID)
	if err != nil {
		return errors.New("error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	sk := requestIKEMessage.Payloads.BuildEncrypted(ikePayload[0].Type(), encryptedData)

	// Calculate checksum
	requestIKEMessageData, err := requestIKEMessage.Encode()
	if err != nil {
		return errors.New("encoding IKE message error")
	}
	checksumOfMessage, err := handler.CalculateChecksum(ikeSecurityAssociation.SK_ai, requestIKEMessageData[:len(requestIKEMessageData)-checksumLength], transformIntegrityAlgorithm.TransformID)
	if err != nil {
		return errors.New("error calculating checksum")
	}
	checksumField := sk.EncryptedData[len(sk.EncryptedData)-checksumLength:]
	copy(checksumField, checksumOfMessage)

	return nil

}

func decryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation, ikeMessage *message.IKEMessage, encryptedPayload *message.Encrypted) (message.IKEPayloadContainer, error) {
	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength := 12 // HMAC_SHA1_96

	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-checksumLength:]

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		return nil, errors.New("encoding IKE message failed")
	}

	ok, err := handler.VerifyIKEChecksum(ikeSecurityAssociation.SK_ar, ikeMessageData[:len(ikeMessageData)-checksumLength], checksum, transformIntegrityAlgorithm.TransformID)
	if err != nil {
		return nil, errors.New("error verify checksum")
	}
	if !ok {
		return nil, errors.New("checksum failed, drop")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-checksumLength]
	plainText, err := handler.DecryptMessage(ikeSecurityAssociation.SK_er, encryptedData, transformEncryptionAlgorithm.TransformID)
	if err != nil {
		return nil, errors.New("error decrypting message")
	}

	var decryptedIKEPayload message.IKEPayloadContainer
	err = decryptedIKEPayload.Decode(encryptedPayload.NextPayload, plainText)
	if err != nil {
		return nil, errors.New("decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil

}

func populateIkeInitSaMessage(ikeMessage *message.IKEMessage, localInitData *LocalIkeSaInitData) error {

	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256
	// Build IKE SA INIT Header
	ikeMessage.BuildIKEHeader(localInitData.localSpi, 0, message.IKE_SA_INIT, message.InitiatorBitCheck, 0)

	// Build SA Payload
	securityAssociation := ikeMessage.Payloads.BuildSecurityAssociation()
	proposal := securityAssociation.Proposals.BuildProposal(1, message.TypeIKE, nil)
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	proposal.PseudorandomFunction.BuildTransform(message.TypePseudorandomFunction, message.PRF_HMAC_SHA1, nil, nil, nil)
	proposal.DiffieHellmanGroup.BuildTransform(message.TypeDiffieHellmanGroup, message.DH_2048_BIT_MODP, nil, nil, nil)

	// Build Key Exchange Payload
	ikeMessage.Payloads.BUildKeyExchange(message.DH_2048_BIT_MODP, localInitData.localPublicKeyExchangeValue)

	// Build Nonce Payload
	ikeMessage.Payloads.BuildNonce(localInitData.localNonce)
	return nil

}

func generateKeyData() (*big.Int, *big.Int, *big.Int, []byte, error) {
	// Key exchange data
	generator := new(big.Int).SetUint64(handler.Group2Generator)
	factor, ok := new(big.Int).SetString(handler.Group14PrimeString, 16)
	if !ok {
		return nil, nil, nil, nil, errors.New("generate key exchange data failed")
	}
	secret := handler.GenerateRandomNumber()
	localPublicKeyExchangeValue := new(big.Int).Exp(generator, secret, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)
	return generator, factor, secret, localPublicKeyExchangeValue, nil
}

func generateInitSignedOctet(ikeSecurityAssociation *context.IKESecurityAssociation, ikeMessageData []byte, remoteNonce []byte) error {

	idPayloadData := append(append([]byte{ikeSecurityAssociation.InitiatorID.IDType}, []byte{0, 0, 0}...),
		ikeSecurityAssociation.InitiatorID.IDData...)
	ikeSecurityAssociation.LocalUnsignedAuthentication = append(ikeMessageData, remoteNonce...)

	pseudorandomFunction, ok := handler.NewPseudorandomFunction(ikeSecurityAssociation.SK_pi,
		ikeSecurityAssociation.PseudorandomFunction.TransformID)
	if !ok {
		return errors.New("Unsupported transform is chosen")
	}

	if _, err := pseudorandomFunction.Write(idPayloadData); err != nil {
		err_str := fmt.Sprintf("Pseudorandom function write error: %+v", err)
		return errors.New(err_str)
	}

	ikeSecurityAssociation.LocalUnsignedAuthentication = append(ikeSecurityAssociation.LocalUnsignedAuthentication,
		pseudorandomFunction.Sum(nil)...)

	logger.IKELog.Tracef("Local unsigned authentication data:\n%s", hex.Dump(ikeSecurityAssociation.LocalUnsignedAuthentication))
	return nil

}

func generateRespSignedOctet(ikeSecurityAssociation *context.IKESecurityAssociation,
	responder ResponderId, ikeMessageData []byte, localNonce []byte) {

	idPayloadData := append(append([]byte{responder.responderType}, []byte{0, 0, 0}...),
		responder.responderData...)
	ikeSecurityAssociation.RemoteUnsignedAuthentication = append(ikeMessageData, localNonce...)

	pseudorandomFunction, ok := handler.NewPseudorandomFunction(ikeSecurityAssociation.SK_pr,
		ikeSecurityAssociation.PseudorandomFunction.TransformID)
	if !ok {
		logger.IKELog.Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
		return
	}

	if _, err := pseudorandomFunction.Write(idPayloadData); err != nil {
		logger.IKELog.Errorf("Pseudorandom function write error: %+v", err)
		return
	}

	ikeSecurityAssociation.RemoteUnsignedAuthentication = append(ikeSecurityAssociation.RemoteUnsignedAuthentication,
		pseudorandomFunction.Sum(nil)...)

	logger.IKELog.Tracef("Local unsigned authentication data:\n%s", hex.Dump(ikeSecurityAssociation.RemoteUnsignedAuthentication))

}

func computeAuthData(ikeSecurityAssociation *context.IKESecurityAssociation) ([]byte, error) {

	pseudorandomFunction, ok := handler.NewPseudorandomFunction([]byte("india"), ikeSecurityAssociation.PseudorandomFunction.TransformID)
	if !ok {
		return nil, errors.New("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
	}
	if _, err := pseudorandomFunction.Write([]byte("Key Pad for IKEv2")); err != nil {
		return nil, errors.New("Pseudorandom function write error: ")
	}
	secret := pseudorandomFunction.Sum(nil)
	pseudorandomFunction, ok = handler.NewPseudorandomFunction(secret, ikeSecurityAssociation.PseudorandomFunction.TransformID)
	if !ok {
		return nil, errors.New("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
	}
	if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.LocalUnsignedAuthentication); err != nil {
		return nil, errors.New("Pseudorandom function write error: ")
	}
	return pseudorandomFunction.Sum(nil), nil
}

func computeAuthDataRemote(ikeSecurityAssociation *context.IKESecurityAssociation) ([]byte, error) {

	pseudorandomFunction, ok := handler.NewPseudorandomFunction([]byte("india"), ikeSecurityAssociation.PseudorandomFunction.TransformID)
	if !ok {
		return nil, errors.New("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
	}
	if _, err := pseudorandomFunction.Write([]byte("Key Pad for IKEv2")); err != nil {
		return nil, errors.New("Pseudorandom function write error: ")
	}
	secret := pseudorandomFunction.Sum(nil)
	pseudorandomFunction, ok = handler.NewPseudorandomFunction(secret, ikeSecurityAssociation.PseudorandomFunction.TransformID)
	if !ok {
		return nil, errors.New("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
	}
	if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.RemoteUnsignedAuthentication); err != nil {
		return nil, errors.New("Pseudorandom function write error: ")
	}
	return pseudorandomFunction.Sum(nil), nil
}

func populateIkeAuthMessage(ikeMessage *message.IKEMessage, ikeSecurityAssociation *context.IKESecurityAssociation,
	ikePayload *message.IKEPayloadContainer, localInitData *LocalIkeSaInitData) error {

	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256

	ikeMessage.BuildIKEHeader(localInitData.localSpi, ikeSecurityAssociation.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, 1)

	// Identification
	ikePayload.BuildIdentificationInitiator(message.ID_IPV4_ADDR, []byte(net.ParseIP(localInitData.localIp).To4()))

	authData, err := computeAuthData(ikeSecurityAssociation)
	if err != nil {
		return err
	}

	ikePayload.BuildAuthentication(message.SharedKeyMesageIntegrityCode, authData)
	ikePayload.BuildNotification(message.TypeNone, message.USE_TRANSPORT_MODE, nil, nil)

	// Security Association
	securityAssociation := ikePayload.BuildSecurityAssociation()
	// Proposal 1
	proposal := securityAssociation.Proposals.BuildProposal(1, message.TypeESP, localInitData.childSaInboundSpi)
	// ENCR
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// ESN
	proposal.ExtendedSequenceNumbers.BuildTransform(message.TypeExtendedSequenceNumbers, message.ESN_NO, nil, nil, nil)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535,
		[]byte(net.ParseIP(localInitData.localIp).To4()), []byte(net.ParseIP(localInitData.localIp).To4()))
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535,
		[]byte(net.ParseIP(localInitData.remoteIp).To4()), []byte(net.ParseIP(localInitData.remoteIp).To4()))

	return nil
}

func populateIkeRekeySaMessage(ikeMessage *message.IKEMessage, localInitData *LocalIkeSaInitData,
	ikeSecurityAssociation *context.IKESecurityAssociation, udpConnection *net.UDPConn) (*context.IKESecurityAssociation, error) {
	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256
	spiToDelete := localInitData.localSpi

	ikeMessage.BuildIKEHeader(ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI, message.CREATE_CHILD_SA, message.InitiatorBitCheck, 2)

	_, factor, secret, localPublicKeyExchangeValue, err := generateKeyData()
	if err != nil {
		fmt.Println("Error occurs when calling generateKeyData() : %+v", err)
	}
	// Generate Local Nonce
	localNonceInt := handler.GenerateRandomNumber()
	if localNonceInt == nil {
		fmt.Println("Error occurs when calling GenerateRandomNumber() for localNonceInt")
	}

	localNonce := localNonceInt.Bytes()

	localSpi := handler.GenerateRandomNumber()
	if localSpi == nil {
		fmt.Println("Error occurs when calling GenerateRandomNumber() for localSpi")
	}
	// Build Key Exchange Payload

	localInitData.localSpi = localSpi.Uint64()
	localInitData.localNonce = localNonce
	localInitData.localPublicKeyExchangeValue = localPublicKeyExchangeValue

	newIKESASPIByte := make([]byte, 8)
	binary.BigEndian.PutUint64(newIKESASPIByte, localInitData.localSpi)

	ikePayload := new(message.IKEPayloadContainer)

	securityAssociation := ikePayload.BuildSecurityAssociation()
	// Proposal 1
	proposal := securityAssociation.Proposals.BuildProposal(1, message.TypeIKE, newIKESASPIByte)
	// ENCR
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// ESN
	proposal.DiffieHellmanGroup.BuildTransform(message.TypeDiffieHellmanGroup, message.DH_2048_BIT_MODP, nil, nil, nil)

	proposal.PseudorandomFunction.BuildTransform(message.TypePseudorandomFunction, message.PRF_HMAC_SHA1, nil, nil, nil)
	ikePayload.BUildKeyExchange(message.DH_2048_BIT_MODP, localInitData.localPublicKeyExchangeValue)

	// Build Nonce Payload
	ikePayload.BuildNonce(localInitData.localNonce)

	if err := encryptProcedure(ikeSecurityAssociation, *ikePayload, ikeMessage); err != nil {
		logger.IKELog.Error("Encrypting IKE message failed:", err)
	}

	_, err = encodeAndSendIkeMessage(ikeMessage, udpConnection)

	decryptedIkeAuthPayload, _ := receiveAndDecryptIkeMessage(udpConnection, ikeSecurityAssociation)

	if decryptedIkeAuthPayload == nil {
		logger.IKELog.Errorf("Error in receiveAndDecryptIkeMessage()")
	}

	var sharedKeyExchangeData []byte
	var remoteNonce []byte
	var respSecurityAssociation *message.SecurityAssociation

	for _, ikePayload := range decryptedIkeAuthPayload {
		switch ikePayload.Type() {
		case message.TypeSA:
			respSecurityAssociation = ikePayload.(*message.SecurityAssociation)
			ikeSecurityAssociation.IKEAuthResponseSA = respSecurityAssociation
		case message.TypeKE:
			remotePublicKeyExchangeValue := ikePayload.(*message.KeyExchange).KeyExchangeData
			var i int = 0
			for {
				if remotePublicKeyExchangeValue[i] != 0 {
					break
				}
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).SetBytes(remotePublicKeyExchangeValue)
			sharedKeyExchangeData = new(big.Int).Exp(remotePublicKeyExchangeValueBig, secret, factor).Bytes()
		case message.TypeNiNr:
			logger.IKELog.Info("Get NiNr")
			remoteNonce = ikePayload.(*message.Nonce).NonceData
		default:
			logger.IKELog.Warnf(
				"Get IKE payload (type %d) in IKE_AUTH message, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	var remoteSPI uint64
	binary.BigEndian.PutUint64(respSecurityAssociation.Proposals[0].SPI, remoteSPI)

	newIkeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:               uint64(localInitData.localSpi),
		RemoteSPI:              remoteSPI,
		EncryptionAlgorithm:    respSecurityAssociation.Proposals[0].EncryptionAlgorithm[0],
		IntegrityAlgorithm:     respSecurityAssociation.Proposals[0].IntegrityAlgorithm[0],
		PseudorandomFunction:   respSecurityAssociation.Proposals[0].PseudorandomFunction[0],
		DiffieHellmanGroup:     respSecurityAssociation.Proposals[0].DiffieHellmanGroup[0],
		ConcatenatedNonce:      append(localInitData.localNonce, remoteNonce...),
		DiffieHellmanSharedKey: sharedKeyExchangeData,
		InitiatorID:            &message.IdentificationInitiator{IDType: 1, IDData: []byte(net.ParseIP(localInitData.localIp).To4())},
	}

	if _, duplicate := n3iwfContext.IKESA.LoadOrStore(localInitData.localSpi, newIkeSecurityAssociation); !duplicate {
		fmt.Println("Value is stored")
	}

	if err := GenerateKeyForIKESARekey(ikeSecurityAssociation, newIkeSecurityAssociation); err != nil {
		logger.IKELog.Errorf("Generate Key for IKE SA Rekey failed with %+v", err)
	}

	deletePayload := new(message.IKEPayloadContainer)

	newIKEMessage := new(message.IKEMessage)
	newIKEMessage.InitiatorSPI = ikeSecurityAssociation.LocalSPI
	newIKEMessage.ResponderSPI = ikeSecurityAssociation.RemoteSPI
	newIKEMessage.MessageID = 3

	BuildIkeSaDeleteMessage(newIKEMessage, ikeSecurityAssociation, deletePayload, true, nil)

	if err := encryptProcedure(ikeSecurityAssociation, *deletePayload, newIKEMessage); err != nil {
		logger.IKELog.Error("Encrypting IKE message failed:", err)
	}

	_, err = encodeAndSendIkeMessage(newIKEMessage, udpConnection)

	decryptedIkeInfoPayload, _ := receiveAndDecryptIkeMessage(udpConnection, ikeSecurityAssociation)

	if decryptedIkeInfoPayload == nil {
		logger.IKELog.Infof("decryptedpayload for delete was none as expected")
	}

	n3iwfContext.IKESA.Delete(spiToDelete)

	return newIkeSecurityAssociation, err

}

func populateChildRekeySaMessage(ikeMessage *message.IKEMessage, localInitData *LocalIkeSaInitData,
	ikeSecurityAssociation *context.IKESecurityAssociation, udpConnection *net.UDPConn) {
	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256

	var inboundSPI uint32
	newInboundSPIByte := make([]byte, 4)
	randomUint64 := handler.GenerateRandomNumber().Uint64()
	inboundSPI = uint32(randomUint64)
	binary.BigEndian.PutUint32(newInboundSPIByte, inboundSPI)

	ikeMessage.BuildIKEHeader(ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI, message.CREATE_CHILD_SA, message.InitiatorBitCheck, 2)

	// Generate Local Nonce
	localNonceInt := handler.GenerateRandomNumber()
	if localNonceInt == nil {
		fmt.Println("Error occurs when calling GenerateRandomNumber() for localNonceInt")
	}

	localNonce := localNonceInt.Bytes()

	localInitData.localNonce = localNonce

	ikePayload := new(message.IKEPayloadContainer)

	ikePayload.BuildNotification(message.TypeESP, message.REKEY_SA, localInitData.childSaInboundSpi, nil)
	securityAssociation := ikePayload.BuildSecurityAssociation()
	// Proposal 1
	proposal := securityAssociation.Proposals.BuildProposal(1, message.TypeESP, newInboundSPIByte)
	// ENCR
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// ESN
	proposal.ExtendedSequenceNumbers.BuildTransform(message.TypeExtendedSequenceNumbers, message.ESN_NO, nil, nil, nil)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535,
		[]byte(net.ParseIP(localInitData.localIp).To4()), []byte(net.ParseIP(localInitData.localIp).To4()))
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535,
		[]byte(net.ParseIP(localInitData.remoteIp).To4()), []byte(net.ParseIP(localInitData.remoteIp).To4()))

	// Build Nonce Payload
	ikePayload.BuildNonce(localInitData.localNonce)

	ikePayload.BuildNotification(message.TypeESP, message.USE_TRANSPORT_MODE, nil, nil)

	if err := encryptProcedure(ikeSecurityAssociation, *ikePayload, ikeMessage); err != nil {
		logger.IKELog.Error("Encrypting IKE message failed:", err)
	}

	_, err := encodeAndSendIkeMessage(ikeMessage, udpConnection)

	if err != nil {
		logger.IKELog.Errorf("Error in encode and send ike message in child sa rekeying")
	}

	decryptedIkeAuthPayload, _ := receiveAndDecryptIkeMessage(udpConnection, ikeSecurityAssociation)

	if decryptedIkeAuthPayload == nil {
		logger.IKELog.Errorf("Error in receiveAndDecryptIkeMessage()")
	}

	// var remoteNonce []byte
	// var respSecurityAssociation *message.SecurityAssociation
	var respTrafficSelectorInitiator *message.TrafficSelectorInitiator
	var respTrafficSelectorResponder *message.TrafficSelectorResponder
	var remoteNonce []byte

	for _, ikePayload := range decryptedIkeAuthPayload {
		switch ikePayload.Type() {
		case message.TypeSA:
			respSecurityAssociation := ikePayload.(*message.SecurityAssociation)
			ikeSecurityAssociation.IKEAuthResponseSA = respSecurityAssociation
		case message.TypeNiNr:
			logger.IKELog.Info("Get NiNr")
			remoteNonce = ikePayload.(*message.Nonce).NonceData
		case message.TypeTSi:
			respTrafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
		case message.TypeTSr:
			respTrafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
		default:
			logger.IKELog.Warnf(
				"Get IKE payload (type %d) in IKE_AUTH message, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	var remoteChildSPI uint32
	fmt.Println(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI)
	remoteChildSPI = binary.BigEndian.Uint32(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI)
	fmt.Println(remoteChildSPI)
	oldChildSASPI := localInitData.childSaInboundSpi
	localInitData.childSaInboundSpi = newInboundSPIByte
	concatenatedNonce := append(localInitData.localNonce, remoteNonce...)

	childSecurityAssociationContext, err := createIKEChildSecurityAssociation(ikeSecurityAssociation.IKEAuthResponseSA, binary.BigEndian.Uint32(localInitData.childSaInboundSpi))
	if err != nil {
		logger.IKELog.Errorf("Create child security association context failed: %+v", err)
	}

	err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContext, localInitData, respTrafficSelectorInitiator.TrafficSelectors[0], respTrafficSelectorResponder.TrafficSelectors[0])
	if err != nil {
		logger.IKELog.Errorf("Parse IP address to child security association failed: %+v", err)
	}

	childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_ICMP

	isCreateChildSA := true

	if err = GenerateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContext, isCreateChildSA, concatenatedNonce); err != nil {
		logger.IKELog.Errorf("Generate key for child SA failed: %+v", err)
		return
	}

	fmt.Println("Flushing policy and state")
	err = netlink.XfrmPolicyFlush()
	if err != nil {
		fmt.Println(err)
	}
	err = netlink.XfrmStateFlush(netlink.XFRM_PROTO_IPSEC_ANY)
	if err != nil {
		fmt.Println(err)
	}

	// Aplly XFRM rules
	if err = applyXFRMRule(true, childSecurityAssociationContext, remoteChildSPI); err != nil {
		logger.IKELog.Errorf("Applying XFRM rules failed: %+v", err)
		return
	}

	deletePayload := new(message.IKEPayloadContainer)

	newIKEMessage := new(message.IKEMessage)
	newIKEMessage.InitiatorSPI = ikeSecurityAssociation.LocalSPI
	newIKEMessage.ResponderSPI = ikeSecurityAssociation.RemoteSPI
	newIKEMessage.MessageID = 3

	BuildIkeSaDeleteMessage(newIKEMessage, ikeSecurityAssociation, deletePayload, false, oldChildSASPI)

	if err := encryptProcedure(ikeSecurityAssociation, *deletePayload, newIKEMessage); err != nil {
		logger.IKELog.Error("Encrypting IKE message failed:", err)
	}

	_, err = encodeAndSendIkeMessage(newIKEMessage, udpConnection)

	decryptedIkeInfoPayload, _ := receiveAndDecryptIkeMessage(udpConnection, ikeSecurityAssociation)

	if decryptedIkeInfoPayload == nil {
		logger.IKELog.Infof("decryptedpayload for delete was none as expected")
	}
}

func GenerateKeyForIKESARekey(oldIkeSecurityAssociation *context.IKESecurityAssociation,
	newIkeSecurityAssociation *context.IKESecurityAssociation) error {
	// Check parameters
	if newIkeSecurityAssociation == nil {
		return errors.New("IKE SA is nil")
	}

	// Check if the context contain needed data
	if newIkeSecurityAssociation.EncryptionAlgorithm == nil {
		return errors.New("No encryption algorithm specified")
	}
	if newIkeSecurityAssociation.IntegrityAlgorithm == nil {
		return errors.New("No integrity algorithm specified")
	}
	if newIkeSecurityAssociation.PseudorandomFunction == nil {
		return errors.New("No pseudorandom function specified")
	}
	if newIkeSecurityAssociation.DiffieHellmanGroup == nil {
		return errors.New("No Diffie-hellman group algorithm specified")
	}

	if len(newIkeSecurityAssociation.ConcatenatedNonce) == 0 {
		return errors.New("No concatenated nonce data")
	}
	if len(newIkeSecurityAssociation.DiffieHellmanSharedKey) == 0 {
		return errors.New("No Diffie-Hellman shared key")
	}

	// Transforms
	transformIntegrityAlgorithm := newIkeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := newIkeSecurityAssociation.EncryptionAlgorithm
	transformPseudorandomFunction := newIkeSecurityAssociation.PseudorandomFunction

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int
	var ok bool

	if length_SK_d, ok = getKeyLength(transformPseudorandomFunction.TransformType,
		transformPseudorandomFunction.TransformID, transformPseudorandomFunction.AttributePresent,
		transformPseudorandomFunction.AttributeValue); !ok {
		logger.IKELog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	if length_SK_ai, ok = getKeyLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue); !ok {
		logger.IKELog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_ar = length_SK_ai
	if length_SK_ei, ok = getKeyLength(transformEncryptionAlgorithm.TransformType,
		transformEncryptionAlgorithm.TransformID, transformEncryptionAlgorithm.AttributePresent,
		transformEncryptionAlgorithm.AttributeValue); !ok {
		logger.IKELog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d
	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	var pseudorandomFunction hash.Hash

	if pseudorandomFunction, ok = handler.NewPseudorandomFunction(oldIkeSecurityAssociation.SK_d,
		oldIkeSecurityAssociation.PseudorandomFunction.TransformID); !ok {
		logger.IKELog.Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
		return errors.New("New pseudorandom function failed")
	}

	logger.IKELog.Tracef("DH shared key:\n%s", hex.Dump(newIkeSecurityAssociation.DiffieHellmanSharedKey))
	logger.IKELog.Tracef("Concatenated nonce:\n%s", hex.Dump(newIkeSecurityAssociation.ConcatenatedNonce))

	if _, err := pseudorandomFunction.Write(newIkeSecurityAssociation.DiffieHellmanSharedKey); err != nil {
		logger.IKELog.Errorf("Pseudorandom function write error: %+v", err)
		return errors.New("Pseudorandom function write failed")
	}

	if _, err := pseudorandomFunction.Write(oldIkeSecurityAssociation.ConcatenatedNonce); err != nil {
		logger.IKELog.Errorf("Pseudorandom function write error: %+v", err)
		return errors.New("Pseudorandom function write failed")
	}

	SKEYSEED := pseudorandomFunction.Sum(nil)

	logger.IKELog.Infof("SKEYSEED:\n%s", hex.Dump(SKEYSEED))

	seed := concatenateNonceAndSPI(newIkeSecurityAssociation.ConcatenatedNonce,
		newIkeSecurityAssociation.LocalSPI, newIkeSecurityAssociation.RemoteSPI)

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok =
			handler.NewPseudorandomFunction(SKEYSEED, transformPseudorandomFunction.TransformID); !ok {
			logger.IKELog.Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			logger.IKELog.Errorf("Pseudorandom function write error: %+v", err)
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	// Assign keys into context
	newIkeSecurityAssociation.SK_d = keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	newIkeSecurityAssociation.SK_ai = keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	newIkeSecurityAssociation.SK_ar = keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	newIkeSecurityAssociation.SK_ei = keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	newIkeSecurityAssociation.SK_er = keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	newIkeSecurityAssociation.SK_pi = keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	newIkeSecurityAssociation.SK_pr = keyStream[:length_SK_pr]
	// keyStream = keyStream[length_SK_pr:]

	logger.IKELog.Infof("SK_d:\n%s", hex.Dump(newIkeSecurityAssociation.SK_d))
	logger.IKELog.Infof("SK_ai:\n%s", hex.Dump(newIkeSecurityAssociation.SK_ai))
	logger.IKELog.Infof("SK_ar:\n%s", hex.Dump(newIkeSecurityAssociation.SK_ar))
	logger.IKELog.Infof("SK_ei:\n%s", hex.Dump(newIkeSecurityAssociation.SK_ei))
	logger.IKELog.Infof("SK_er:\n%s", hex.Dump(newIkeSecurityAssociation.SK_er))
	logger.IKELog.Infof("SK_pi:\n%s", hex.Dump(newIkeSecurityAssociation.SK_pi))
	logger.IKELog.Infof("SK_pr:\n%s", hex.Dump(newIkeSecurityAssociation.SK_pr))

	return nil
}

func printSAInfo(n3iwf_is_initiator bool, childSecurityAssociation *context.ChildSecurityAssociation, outBoundSPI uint32) {
	var InboundEncryptionKey, InboundIntegrityKey, OutboundEncryptionKey, OutboundIntegrityKey []byte

	if n3iwf_is_initiator {
		InboundEncryptionKey = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		InboundIntegrityKey = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		OutboundEncryptionKey = childSecurityAssociation.InitiatorToResponderEncryptionKey
		OutboundIntegrityKey = childSecurityAssociation.InitiatorToResponderIntegrityKey
	} else {
		InboundEncryptionKey = childSecurityAssociation.InitiatorToResponderEncryptionKey
		InboundIntegrityKey = childSecurityAssociation.InitiatorToResponderIntegrityKey
		OutboundEncryptionKey = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		OutboundIntegrityKey = childSecurityAssociation.ResponderToInitiatorIntegrityKey
	}
	logger.IKELog.Infof("====== IPSec/Child SA Info ======")
	// ====== Inbound ======
	// logger.IKELog.Debugf("XFRM interface if_id: %d", xfrmiId)
	logger.IKELog.Infof("IPSec Inbound  SPI: 0x%016x", childSecurityAssociation.SPI)
	logger.IKELog.Infof("[UE:%+v] -> [N3IWF:%+v]",
		childSecurityAssociation.PeerPublicIPAddr, childSecurityAssociation.LocalPublicIPAddr)
	logger.IKELog.Infof("IPSec Encryption Algorithm: %d", childSecurityAssociation.EncryptionAlgorithm)
	logger.IKELog.Infof("IPSec Encryption Key: 0x%x", InboundEncryptionKey)
	logger.IKELog.Infof("IPSec Integrity  Algorithm: %d", childSecurityAssociation.IntegrityAlgorithm)
	logger.IKELog.Infof("IPSec Integrity  Key: 0x%x", InboundIntegrityKey)
	logger.IKELog.Infof("====== IPSec/Child SA Info ======")
	// ====== Outbound ======
	// logger.IKELog.Debugf("XFRM interface if_id: %d", xfrmiId)
	logger.IKELog.Infof("IPSec Outbound  SPI: 0x%016x", outBoundSPI)
	logger.IKELog.Infof("[N3IWF:%+v] -> [UE:%+v]",
		childSecurityAssociation.LocalPublicIPAddr, childSecurityAssociation.PeerPublicIPAddr)
	logger.IKELog.Infof("IPSec Encryption Algorithm: %d", childSecurityAssociation.EncryptionAlgorithm)
	logger.IKELog.Infof("IPSec Encryption Key: 0x%x", OutboundEncryptionKey)
	logger.IKELog.Infof("IPSec Integrity  Algorithm: %d", childSecurityAssociation.IntegrityAlgorithm)
	logger.IKELog.Infof("IPSec Integrity  Key: 0x%x", OutboundIntegrityKey)
}

func applyXFRMRule(ueIsInitiator bool, childSecurityAssociation *context.ChildSecurityAssociation, outBoundSPI uint32) error {
	// Build XFRM information data structure for incoming traffic.

	// Mark
	// mark := &netlink.XfrmMark{
	// 	Value: 5,
	// }

	// Direction: N3IWF -> UE
	// State
	var xfrmEncryptionAlgorithm, xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if ueIsInitiator {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: handler.XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: handler.XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.ResponderToInitiatorIntegrityKey,
			}
		}
	} else {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: handler.XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.InitiatorToResponderEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: handler.XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.InitiatorToResponderIntegrityKey,
			}
		}
	}

	logger.IKELog.Infof("CA Enc. Alg. %s", childSecurityAssociation.EncryptionAlgorithm)
	logger.IKELog.Infof("CA Intg. Alg. %s", childSecurityAssociation.IntegrityAlgorithm)
	logger.IKELog.Infof("CA InitiatorToResponderEncryptionKey %s", childSecurityAssociation.InitiatorToResponderEncryptionKey)

	xfrmState := new(netlink.XfrmState)

	xfrmState.Src = childSecurityAssociation.PeerPublicIPAddr
	xfrmState.Dst = childSecurityAssociation.LocalPublicIPAddr
	xfrmState.Proto = netlink.XFRM_PROTO_ESP
	xfrmState.Mode = netlink.XFRM_MODE_TRANSPORT
	xfrmState.Spi = int(childSecurityAssociation.SPI)
	// xfrmState.Mark = mark
	xfrmState.Auth = xfrmIntegrityAlgorithm
	xfrmState.Crypt = xfrmEncryptionAlgorithm
	xfrmState.ESN = childSecurityAssociation.ESN
	logger.IKELog.Infof("Setting XFRM with PeerPublicIPAddr %s and LocalPublicIPAddr %s and SPI %d and ESN %s", xfrmState.Src, xfrmState.Dst, int(childSecurityAssociation.SPI), xfrmState.ESN)
	logger.IKELog.Infof("XFRM state string: %s", xfrmState.String())

	// Commit xfrm state to netlink
	var err error
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("set XFRM state rule failed 1: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate := netlink.XfrmPolicyTmpl{
		Src:   xfrmState.Src,
		Dst:   xfrmState.Dst,
		Proto: xfrmState.Proto,
		Mode:  xfrmState.Mode,
		Spi:   xfrmState.Spi,
	}

	xfrmPolicy := new(netlink.XfrmPolicy)

	// if childSecurityAssociation.SelectedIPProtocol == 0 {
	// 	return errors.New("protocol == 0")
	// }

	xfrmPolicy.Src = &childSecurityAssociation.TrafficSelectorRemote
	xfrmPolicy.Dst = &childSecurityAssociation.TrafficSelectorLocal
	xfrmPolicy.Proto = netlink.Proto(childSecurityAssociation.SelectedIPProtocol)
	xfrmPolicy.Dir = netlink.XFRM_DIR_IN
	// xfrmPolicy.Mark = mark
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	logger.IKELog.Infof("XFRM Policy string: %s\n", xfrmPolicy.String())

	// if err = netlink.XfrmPolicyDel(xfrmPolicy); err != nil {
	// 	return fmt.Errorf("set XFRM policy rule failed: %+v", err)
	// }

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("set XFRM policy rule failed: %+v", err)
	}

	// Direction: UE -> N3IWF
	// State
	if ueIsInitiator {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.InitiatorToResponderEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.InitiatorToResponderIntegrityKey
		}
	} else {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		}
	}

	xfrmState.Src, xfrmState.Dst = xfrmState.Dst, xfrmState.Src
	xfrmState.Spi = int(outBoundSPI)
	logger.IKELog.Infof("Src: %v, Dst: %v", xfrmState.Src, xfrmState.Dst)

	logger.IKELog.Infof("XFRM state string: %s", xfrmState.String())

	// Commit xfrm state to netlink
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("set XFRM state rule failed 2: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate.Src, xfrmPolicyTemplate.Dst = xfrmPolicyTemplate.Dst, xfrmPolicyTemplate.Src
	xfrmPolicyTemplate.Spi = int(outBoundSPI)

	xfrmPolicy.Src, xfrmPolicy.Dst = xfrmPolicy.Dst, xfrmPolicy.Src
	xfrmPolicy.Dir = netlink.XFRM_DIR_OUT
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	logger.IKELog.Infof("XFRM Policy string: %s\n", xfrmPolicy.String())

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("set XFRM policy rule failed: %+v", err)
	}

	return nil
}

func encodeAndSendIkeMessage(ikeMessage *message.IKEMessage, udpConnection *net.UDPConn) ([]byte, error) {
	// Send to Peer
	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		return nil, errors.New(err.Error())
	}

	if _, err := udpConnection.Write(ikeMessageData); err != nil {
		return nil, errors.New(err.Error())
	}
	return ikeMessageData, nil
}

func receiveAndDecodeIkeMessage(ikeMessage *message.IKEMessage, udpConnection *net.UDPConn) ([]byte, error) {
	// Receive Peer reply
	buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(buffer)
	if err != nil {
		return nil, errors.New(err.Error())
	} else {
		logger.IKELog.Infof("Received non empty response")
	}
	// Used to compute responder auth message
	receivedMessage := buffer[:n]

	// ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(receivedMessage)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return receivedMessage, nil

}

func receiveAndDecryptIkeMessage(udpConnection *net.UDPConn,
	ikeSecurityAssociation *context.IKESecurityAssociation) (message.IKEPayloadContainer, *message.IKEMessage) {

	receivedIkeMessage := new(message.IKEMessage)
	if _, err := receiveAndDecodeIkeMessage(receivedIkeMessage, udpConnection); err != nil {
		logger.IKELog.Errorf("Error occurs when calling receiveAndDecodeIkeMessage(): %+v", err)
		return nil, nil
	} else {
		logger.IKELog.Infof("Success occurs when calling receiveAndDecodeIkeMessage()()")
	}

	encryptedPayload, ok := receivedIkeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		logger.IKELog.Error("Received payload is not an encrypted payload")
		return nil, receivedIkeMessage
	}
	decryptedIKEPayload, err := decryptProcedure(ikeSecurityAssociation, receivedIkeMessage, encryptedPayload)
	if err != nil {
		logger.IKELog.Errorf("Decrypt IKE message failed: %+v", err)
		return nil, receivedIkeMessage
	}
	return decryptedIKEPayload, receivedIkeMessage
}

func concatenateNonceAndSPI(nonce []byte, SPI_initiator uint64, SPI_responder uint64) []byte {
	spi := make([]byte, 8)

	binary.BigEndian.PutUint64(spi, SPI_initiator)
	newSlice := append(nonce, spi...)
	binary.BigEndian.PutUint64(spi, SPI_responder)
	newSlice = append(newSlice, spi...)

	return newSlice
}

func GenerateKeyForIKESA(ikeSecurityAssociation *context.IKESecurityAssociation) error {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return errors.New("IKE SA is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.EncryptionAlgorithm == nil {
		return errors.New("No encryption algorithm specified")
	}
	if ikeSecurityAssociation.IntegrityAlgorithm == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikeSecurityAssociation.PseudorandomFunction == nil {
		return errors.New("No pseudorandom function specified")
	}
	if ikeSecurityAssociation.DiffieHellmanGroup == nil {
		return errors.New("No Diffie-hellman group algorithm specified")
	}

	if len(ikeSecurityAssociation.ConcatenatedNonce) == 0 {
		return errors.New("No concatenated nonce data")
	}
	if len(ikeSecurityAssociation.DiffieHellmanSharedKey) == 0 {
		return errors.New("No Diffie-Hellman shared key")
	}

	// Transforms
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int
	var ok bool

	if length_SK_d, ok = getKeyLength(transformPseudorandomFunction.TransformType,
		transformPseudorandomFunction.TransformID, transformPseudorandomFunction.AttributePresent,
		transformPseudorandomFunction.AttributeValue); !ok {
		logger.IKELog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	if length_SK_ai, ok = getKeyLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue); !ok {
		logger.IKELog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_ar = length_SK_ai
	if length_SK_ei, ok = getKeyLength(transformEncryptionAlgorithm.TransformType,
		transformEncryptionAlgorithm.TransformID, transformEncryptionAlgorithm.AttributePresent,
		transformEncryptionAlgorithm.AttributeValue); !ok {
		logger.IKELog.Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d
	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	var pseudorandomFunction hash.Hash

	if pseudorandomFunction, ok = handler.NewPseudorandomFunction(ikeSecurityAssociation.ConcatenatedNonce,
		transformPseudorandomFunction.TransformID); !ok {
		logger.IKELog.Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
		return errors.New("New pseudorandom function failed")
	}

	logger.IKELog.Tracef("DH shared key:\n%s", hex.Dump(ikeSecurityAssociation.DiffieHellmanSharedKey))
	logger.IKELog.Tracef("Concatenated nonce:\n%s", hex.Dump(ikeSecurityAssociation.ConcatenatedNonce))

	if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.DiffieHellmanSharedKey); err != nil {
		logger.IKELog.Errorf("Pseudorandom function write error: %+v", err)
		return errors.New("Pseudorandom function write failed")
	}

	SKEYSEED := pseudorandomFunction.Sum(nil)

	logger.IKELog.Tracef("SKEYSEED:\n%s", hex.Dump(SKEYSEED))

	seed := concatenateNonceAndSPI(ikeSecurityAssociation.ConcatenatedNonce,
		ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI)

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok =
			handler.NewPseudorandomFunction(SKEYSEED, transformPseudorandomFunction.TransformID); !ok {
			logger.IKELog.Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			logger.IKELog.Errorf("Pseudorandom function write error: %+v", err)
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	// Assign keys into context
	ikeSecurityAssociation.SK_d = keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	ikeSecurityAssociation.SK_ai = keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	ikeSecurityAssociation.SK_ar = keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	ikeSecurityAssociation.SK_ei = keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	ikeSecurityAssociation.SK_er = keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	ikeSecurityAssociation.SK_pi = keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	ikeSecurityAssociation.SK_pr = keyStream[:length_SK_pr]
	// keyStream = keyStream[length_SK_pr:]

	logger.IKELog.Tracef("SK_d:\n%s", hex.Dump(ikeSecurityAssociation.SK_d))
	logger.IKELog.Tracef("SK_ai:\n%s", hex.Dump(ikeSecurityAssociation.SK_ai))
	logger.IKELog.Tracef("SK_ar:\n%s", hex.Dump(ikeSecurityAssociation.SK_ar))
	logger.IKELog.Tracef("SK_ei:\n%s", hex.Dump(ikeSecurityAssociation.SK_ei))
	logger.IKELog.Tracef("SK_er:\n%s", hex.Dump(ikeSecurityAssociation.SK_er))
	logger.IKELog.Tracef("SK_pi:\n%s", hex.Dump(ikeSecurityAssociation.SK_pi))
	logger.IKELog.Tracef("SK_pr:\n%s", hex.Dump(ikeSecurityAssociation.SK_pr))

	return nil
}

func BuildDeletePayload(container *message.IKEPayloadContainer, protocolID uint8,
	SPISize uint8, numberOfSPI uint16, SPI []byte) *message.IKEPayloadContainer {
	deletePayload := new(message.Delete)
	deletePayload.ProtocolID = protocolID
	deletePayload.SPISize = SPISize
	deletePayload.NumberOfSPI = numberOfSPI
	deletePayload.SPIs = SPI
	*container = append(*container, deletePayload)
	return container
}

func BuildIkeSaDeleteMessage(ikeMessage *message.IKEMessage, ikeSaContext *context.IKESecurityAssociation,
	ikeSaDeletePayload *message.IKEPayloadContainer, isIKE bool, SPI []byte) {

	ikeMessage.BuildIKEHeader(ikeMessage.InitiatorSPI, ikeMessage.ResponderSPI, message.INFORMATIONAL,
		message.InitiatorBitCheck, ikeMessage.MessageID)

	if isIKE {
		ikeSaDeletePayload = BuildDeletePayload(ikeSaDeletePayload, message.TypeIKE, 0, 0, nil)
		return
	}

	ikeSaDeletePayload = BuildDeletePayload(ikeSaDeletePayload, message.TypeESP, 4, 1, SPI)
}

type LocalIkeSaInitData struct {
	localSpi                    uint64
	childSaInboundSpi           []byte
	localIp                     string
	remoteIp                    string
	localPublicKeyExchangeValue []byte
	localNonce                  []byte
}

func main() {
	var sharedKeyExchangeData []byte
	var remoteNonce []byte

	// Populating the IKE message
	ikeMessage := new(message.IKEMessage)

	// Generate Key exchange data
	_, factor, secret, localPublicKeyExchangeValue, err := generateKeyData()
	if err != nil {
		logger.IKELog.Errorf("Error occurs when calling generateKeyData() : %+v", err)
	}
	// Generate Local Nonce
	localNonceInt := handler.GenerateRandomNumber()
	if localNonceInt == nil {
		logger.IKELog.Errorf("Error occurs when calling GenerateRandomNumber() for localNonceInt")
	}

	localNonce := localNonceInt.Bytes()

	localSpi := handler.GenerateRandomNumber()
	if localSpi == nil {
		logger.IKELog.Errorf("Error occurs when calling GenerateRandomNumber() for localSpi")
	}

	// Generate SPI inbound for child SA
	var inboundSPI uint32
	inboundSPIByte := make([]byte, 4)
	randomUint64 := handler.GenerateRandomNumber().Uint64()
	inboundSPI = uint32(randomUint64)
	binary.BigEndian.PutUint32(inboundSPIByte, inboundSPI)

	localInitData := &LocalIkeSaInitData{
		localSpi:                    localSpi.Uint64(),
		childSaInboundSpi:           inboundSPIByte,
		localIp:                     "192.168.65.2",
		remoteIp:                    "192.168.65.3",
		localPublicKeyExchangeValue: localPublicKeyExchangeValue,
		localNonce:                  localNonce,
	}

	udpConnection, err := setupUDPSocket(localInitData)
	if err != nil {
		logger.IKELog.Errorf("Error occurs when calling setupUDPSocket(): %+v", err)
	}

	// Generate IKE INIT SA Request Message
	if err := populateIkeInitSaMessage(ikeMessage, localInitData); err != nil {
		logger.IKELog.Errorf("Error occurs when calling populateIkeInitSaMessage(): %+v", err)
	}

	ikeMessageData, err := encodeAndSendIkeMessage(ikeMessage, udpConnection)

	if err != nil {
		logger.IKELog.Errorf("Error occurs when calling encodeAndSendIkeMessage(): %+v", err)
	} else {
		logger.IKELog.Infof("Success occurs when calling encodeAndSendIkeMessage()")
	}

	// time.Sleep(10 * time.Second)

	receivedIkeMessage := new(message.IKEMessage)
	receivedIkeMessageData, err := receiveAndDecodeIkeMessage(receivedIkeMessage, udpConnection)
	if err != nil {
		logger.IKELog.Errorf("Error occurs when calling receiveAndDecodeIkeMessage(): %+v", err)
	} else {
		logger.IKELog.Infof("Success occurs when calling receiveAndDecodeIkeMessage()()")
	}

	var receivedSaProposal *message.Proposal

	for _, ikePayload := range receivedIkeMessage.Payloads {
		switch ikePayload.Type() {
		case message.TypeSA:
			logger.IKELog.Info("Get SA payload")
			receivedSaProposal = ikePayload.(*message.SecurityAssociation).Proposals[0]
		case message.TypeKE:
			remotePublicKeyExchangeValue := ikePayload.(*message.KeyExchange).KeyExchangeData
			var i int = 0
			for {
				if remotePublicKeyExchangeValue[i] != 0 {
					break
				}
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).SetBytes(remotePublicKeyExchangeValue)
			sharedKeyExchangeData = new(big.Int).Exp(remotePublicKeyExchangeValueBig, secret, factor).Bytes()
		case message.TypeNiNr:
			logger.IKELog.Info("Get NiNr")
			remoteNonce = ikePayload.(*message.Nonce).NonceData
		}
	}

	ikeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:               uint64(localInitData.localSpi),
		RemoteSPI:              receivedIkeMessage.ResponderSPI,
		EncryptionAlgorithm:    receivedSaProposal.EncryptionAlgorithm[0],
		IntegrityAlgorithm:     receivedSaProposal.IntegrityAlgorithm[0],
		PseudorandomFunction:   receivedSaProposal.PseudorandomFunction[0],
		DiffieHellmanGroup:     receivedSaProposal.DiffieHellmanGroup[0],
		ConcatenatedNonce:      append(localNonce, remoteNonce...),
		DiffieHellmanSharedKey: sharedKeyExchangeData,
		InitiatorID:            &message.IdentificationInitiator{IDType: 1, IDData: []byte(net.ParseIP(localInitData.localIp).To4())},
	}

	if _, duplicate := n3iwfContext.IKESA.LoadOrStore(localInitData.localSpi, ikeSecurityAssociation); !duplicate {
		fmt.Println("Value is stored")
	}

	if err := GenerateKeyForIKESA(ikeSecurityAssociation); err != nil {
		logger.IKELog.Errorf("Generate key for IKE SA failed: %+v", err)
	}

	if err = generateInitSignedOctet(ikeSecurityAssociation, ikeMessageData, remoteNonce); err != nil {
		logger.IKELog.Errorf("generateInitSignedOctet failed: %+v", err)
	}

	// IKE_AUTH
	var ikePayload message.IKEPayloadContainer
	ikeMessage.Payloads.Reset()

	err = populateIkeAuthMessage(ikeMessage, ikeSecurityAssociation, &ikePayload, localInitData)
	if err != nil {
		logger.IKELog.Error(err)
	}

	if err := encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		logger.IKELog.Error("Encrypting IKE message failed:", err)
	}

	_, err = encodeAndSendIkeMessage(ikeMessage, udpConnection)

	decryptedIkeAuthPayload, _ := receiveAndDecryptIkeMessage(udpConnection, ikeSecurityAssociation)

	if decryptedIkeAuthPayload == nil {
		logger.IKELog.Errorf("Error in receiveAndDecryptIkeMessage()")
	}

	// parseReceivedPayload(decryptedIKEPayload)

	var responder ResponderId
	// var certificateRequest *ike_message.CertificateRequest
	// var certificate *ike_message.Certificate
	var respSecurityAssociation *message.SecurityAssociation
	var respTrafficSelectorInitiator *message.TrafficSelectorInitiator
	var respTrafficSelectorResponder *message.TrafficSelectorResponder
	// var eap *ike_message.EAP
	var authentication *message.Authentication
	// var configuration *ike_message.Configuration

	for _, ikePayload := range decryptedIkeAuthPayload {
		switch ikePayload.Type() {
		case message.TypeIDr:
			logger.IKELog.Info("ID responder payload")
			responder = ResponderId{responderType: ikePayload.(*message.IdentificationResponder).IDType,
				responderData: ikePayload.(*message.IdentificationResponder).IDData}
		// case ike_message.TypeCERTreq:
		// 	certificateRequest = ikePayload.(*ike_message.CertificateRequest)
		// case ike_message.TypeCERT:
		// 	certificate = ikePayload.(*ike_message.Certificate)
		case message.TypeSA:
			respSecurityAssociation = ikePayload.(*message.SecurityAssociation)
			ikeSecurityAssociation.IKEAuthResponseSA = respSecurityAssociation
		case message.TypeTSi:
			respTrafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
		case message.TypeTSr:
			respTrafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
		// case ike_message.TypeEAP:
		// 	eap = ikePayload.(*ike_message.EAP)
		case message.TypeAUTH:
			authentication = ikePayload.(*message.Authentication)
		// case ike_message.TypeCP:
		// 	configuration = ikePayload.(*ike_message.Configuration)
		default:
			logger.IKELog.Warnf(
				"Get IKE payload (type %d) in IKE_AUTH message, this payload will not be handled by IKE handler",
				ikePayload.Type())
		}
	}

	outBoundSPI := binary.BigEndian.Uint32(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI)

	generateRespSignedOctet(ikeSecurityAssociation, responder, receivedIkeMessageData, localNonce)
	//fmt.Println(receivedIkeMessage)

	remoteAuthData, err := computeAuthDataRemote(ikeSecurityAssociation)
	if err != nil {
		logger.IKELog.Error(err)
	}

	if authentication != nil {
		logger.IKELog.Infof("Expected Authentication Data:\n%s", hex.Dump(remoteAuthData))
		logger.IKELog.Infof("Expected Authentication Data:\n%s", hex.Dump(authentication.AuthenticationData))
		if !bytes.Equal(authentication.AuthenticationData, remoteAuthData) {
			logger.IKELog.Error("Auth data of responder not same")
		} else {
			logger.IKELog.Info("Auth data of responder is same")
		}
	}

	childSecurityAssociationContext, err := createIKEChildSecurityAssociation(ikeSecurityAssociation.IKEAuthResponseSA, binary.BigEndian.Uint32(localInitData.childSaInboundSpi))
	if err != nil {
		logger.IKELog.Errorf("Create child security association context failed: %+v", err)
	}

	err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContext, localInitData, respTrafficSelectorInitiator.TrafficSelectors[0], respTrafficSelectorResponder.TrafficSelectors[0])
	if err != nil {
		logger.IKELog.Errorf("Parse IP address to child security association failed: %+v", err)
	}

	childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_ICMP

	if err = GenerateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContext, false, nil); err != nil {
		logger.IKELog.Errorf("Generate key for child SA failed: %+v", err)
		return
	}

	// Aplly XFRM rules
	if err = applyXFRMRule(true, childSecurityAssociationContext, outBoundSPI); err != nil {
		logger.IKELog.Errorf("Applying XFRM rules failed: %+v", err)
		return
	}

	printSAInfo(true, childSecurityAssociationContext, outBoundSPI)

	// udpConnection.Close()

	time.Sleep(30 * time.Second)

	childSARekeyMessage := new(message.IKEMessage)

	populateChildRekeySaMessage(childSARekeyMessage, localInitData, ikeSecurityAssociation, udpConnection)

	// ikeMessage.Payloads.Reset()

	// newIKESecurityAssociation, err := populateIkeRekeySaMessage(ikeMessage, localInitData, ikeSecurityAssociation, udpConnection)

	// ikeMessage.InitiatorSPI = newIKESecurityAssociation.LocalSPI
	// ikeMessage.ResponderSPI = newIKESecurityAssociation.RemoteSPI
	// ikeMessage.MessageID = 0
	// ikeMessage.Flags = message.InitiatorBitCheck
	// ikeMessage.ExchangeType = message.INFORMATIONAL

	// newPayload := new(message.IKEPayloadContainer)

	// newPayload.BuildNotification(message.TypeIKE, message.USE_TRANSPORT_MODE, nil, nil)

	// if err := encryptProcedure(newIKESecurityAssociation, *newPayload, ikeMessage); err != nil {
	// 	logger.IKELog.Error("Encrypting IKE message failed:", err)
	// }

	// _, err = encodeAndSendIkeMessage(ikeMessage, udpConnection)

	// newDecryptedIkeAuthPayload, _ := receiveAndDecryptIkeMessage(udpConnection, newIKESecurityAssociation)

	// if newDecryptedIkeAuthPayload == nil {
	// 	logger.IKELog.Errorf("Error in receiveAndDecryptIkeMessage()")
	// }

	// time.Sleep(30 * time.Second)

	// defer func() {
	// 	fmt.Println("Flushing policy and state")
	// 	err := netlink.XfrmPolicyFlush()
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	}
	// 	err = netlink.XfrmStateFlush(netlink.XFRM_PROTO_IPSEC_ANY)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	}
	// }()

	// ikeMessage.Payloads.Reset()
	// ikeSaDeletePayload := new(message.IKEPayloadContainer)

	// BuildIkeSaDeleteMessage(ikeMessage, ikeSecurityAssociation, ikeSaDeletePayload)

	// if err := encryptProcedure(ikeSecurityAssociation, *ikeSaDeletePayload, ikeMessage); err != nil {
	// 	logger.IKELog.Error("Encrypting IKE message failed:", err)
	// }

	// _, err = encodeAndSendIkeMessage(ikeMessage, udpConnection)

	// decryptedIkeInfoPayload, _ := receiveAndDecryptIkeMessage(udpConnection, ikeSecurityAssociation)

	// if decryptedIkeInfoPayload == nil {
	// 	logger.IKELog.Infof("decryptedpayload for delete was none as expected")
	// }

}
