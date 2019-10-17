package tlsresult

import "errors"

type ChangeCipherSpec uint8

const(
	ChangeCipherSpecType TlsType = 20
	ChangeCipherSpecMessage ChangeCipherSpec = 1
	ChangeCipherSpecUnknown ChangeCipherSpec = 255
)

func (ccs ChangeCipherSpec) String() string {
	switch ccs {
	case ChangeCipherSpecMessage:
		return "Change Cipher Spec Message"
	default:
		return "Unknown"
	}
}

type ChangeCipherSpecRecord struct {
	Message ChangeCipherSpec
}

func (ccs *ChangeCipherSpecRecord) decodeChangeCipherSpec(data []byte) (err error) {
	if len(data) != 1 {
		return errors.New("TLS Change Cipher Spec invalid")
	}
	ccs.Message = ChangeCipherSpec(data[0])
	if ccs.Message != ChangeCipherSpecMessage {
		ccs.Message = ChangeCipherSpecUnknown
	}
	return nil
}

