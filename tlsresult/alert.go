package tlsresult

import "errors"

type AlertLevel              uint8
type AlertDescription        uint8

const (
	AlertType TlsType = 21

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

type AlertRecord struct {
	Level AlertLevel
	Description AlertDescription
}

func (a *AlertRecord) decodeAlert(data []byte) (err error) {
	if len(data) < 2 {
		return errors.New("TLS Alert record too short")
	}
	if len(data) == 2 {
		a.Level = AlertLevel(data[0])
		a.Description = AlertDescription(data[1])
	} else {
		return errors.New("TLS Alert record is invalid")
	}
	return nil
}
