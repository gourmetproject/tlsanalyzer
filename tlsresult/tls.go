package tlsresult

import "encoding/binary"

type TlsType                 uint8
type TlsVersion              uint16
type HandshakeMessageType    uint8
type AlertLevel              uint8
type AlertDescription        uint8

const (
	ChangeCipherSpecType TlsType = 20
	AlertType            TlsType = 21
	HandshakeType        TlsType = 22
	ApplicationType      TlsType = 23
	HeartbeatType        TlsType = 24

	SSL30 TlsVersion = 0
	TLS10 TlsVersion = 1
	TLS11 TlsVersion = 2
	TLS12 TlsVersion = 3
	TLS13 TlsVersion = 4

	HelloRequest       HandshakeMessageType = 0
	ClientHello        HandshakeMessageType = 1
	ServerHello        HandshakeMessageType = 2
	NewSessionTicket   HandshakeMessageType = 4
	EncryptedExtension HandshakeMessageType = 8
	Certificate        HandshakeMessageType = 11
	ServerKeyExchange  HandshakeMessageType = 12
	CertificateRequest HandshakeMessageType = 13
	ServerHelloDone    HandshakeMessageType = 14
	CertificateVerify  HandshakeMessageType = 15
	ClientKeyExchange  HandshakeMessageType = 16
	Finished           HandshakeMessageType = 20

	Warning AlertLevel = 1
	Fatal   AlertLevel = 2

	CloseNotify   AlertDescription = 0
	UnexpectedMsg AlertDescription = 10
	BadRecordMAC  AlertDescription = 20
	DecryptionFailed AlertDescription = 21
	RecordOverflow   AlertDescription = 22
	DecompressionFailure AlertDescription = 30
	HandshakeFailure AlertDescription = 40
	NoCertificate AlertDescription = 41
	BadCertificate AlertDescription = 42
	UnsupportedCertificate AlertDescription = 43
	CertificateRevoked AlertDescription = 44
	CertificateExpired AlertDescription = 45
	CertificateUnknown AlertDescription = 46
	IllegalParameter   AlertDescription = 47
	UnknownCA AlertDescription = 48
	AccessDenied AlertDescription = 49
	DecodeError AlertDescription = 50
	DecryptError AlertDescription = 51
	ExportRestriction AlertDescription = 60
	ProtocolVersion AlertDescription = 70
	InsufficientSecurity AlertDescription = 71
	InternalError AlertDescription = 80
	InappropriateFallback AlertDescription = 86
	UserCanceled AlertDescription = 90
	NoRenegotiation AlertDescription = 100
	UnsupportedExtension AlertDescription = 110
	CertificateUnobtainable AlertDescription = 111
	UnrecognizedName AlertDescription = 112
	BadCertStatusResponse AlertDescription = 113
	BadCertHashValue AlertDescription = 114
	UnknownPSKIdentity AlertDescription = 115
	NoApplicationProtocol AlertDescription = 120
)

type TlsMessage struct {
	Type    TlsType
	Version TlsVersion
	Message Message
}

type TlsApplicationData struct {
	Type TlsType
	Version TlsVersion
	Data ApplicationData
}

type TlsAlert struct {
	Type TlsType
	Version TlsVersion
	Alert Alert
}

type TlsChangeCipherSpec struct {
	Type TlsType
	Version TlsVersion
}

type Message struct {
	MessageLength [3]uint8
	MessageData   []byte
}

type Alert struct {
	Level AlertLevel
	Description AlertDescription
}

type ApplicationData struct {
	Length uint16
	Data   []byte
	MAC    []byte
	Padding []byte
}

func DecodeTlsMessage(payload []byte) (msg *TlsMessage, decoded uint16, err error) {
	tlsType := TlsType(payload[0])
	tlsVersion := TlsVersion(payload[2])
	length := binary.BigEndian.Uint16(payload[3:5])
	msg = &TlsMessage{
		Type:    tlsType,
		Version: tlsVersion,
	}
	return msg, length + 5, nil
}

func DecodeTlsApplicationData(payload []byte) (appData *TlsApplicationData, decoded uint16, err error) {
	tlsType := TlsType(payload[0])
	tlsVersion := TlsVersion(payload[2])
	length := binary.BigEndian.Uint16(payload[3:5])
	appData = &TlsApplicationData{
		Type:    tlsType,
		Version: tlsVersion,
	}
	return appData, length + 5, nil
}

func DecodeTlsAlert(payload []byte) (alert *TlsAlert, decoded uint16, err error) {
	tlsType := TlsType(payload[0])
	tlsVersion := TlsVersion(payload[2])
	length := binary.BigEndian.Uint16(payload[3:5])
	alert = &TlsAlert{
		Type:    tlsType,
		Version: tlsVersion,
	}
	return alert, length + 5, nil
}

func DecodeChangeCipherSpec(payload []byte) (ccs *TlsChangeCipherSpec, decoded uint16, err error) {
	tlsType := TlsType(payload[0])
	tlsVersion := TlsVersion(payload[2])
	length := binary.BigEndian.Uint16(payload[3:5])
	ccs = &TlsChangeCipherSpec{
		Type:    tlsType,
		Version: tlsVersion,
	}
	return ccs, length + 5, nil
}

func DecodeTlsPayload(payload []byte) (decodedTls []interface{}, err error) {
	var nextMessageStart, decoded uint16
	var decodedRecord interface{}
	tlsType := TlsType(payload[0])
	bytesLeft := uint16(len(payload))
	for bytesLeft > 0 {
		payloadChunk := payload[nextMessageStart:]
		switch tlsType {
		case HandshakeType:
			decodedRecord, decoded, err = DecodeTlsMessage(payloadChunk)
		case AlertType:
			decodedRecord, decoded, err = DecodeTlsAlert(payloadChunk)
		case ApplicationType:
			decodedRecord, decoded, err = DecodeTlsApplicationData(payloadChunk)
		case ChangeCipherSpecType:
			decodedRecord, decoded, err = DecodeChangeCipherSpec(payloadChunk)
		}
		if decoded == 0 || err != nil {
			break
		}
		decodedTls = append(decodedTls, decodedRecord)
		bytesLeft -= decoded
		nextMessageStart += decoded
	}
	return decodedTls, err
}