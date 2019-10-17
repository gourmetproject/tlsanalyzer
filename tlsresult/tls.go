/*
tlsresult is a package that decodes TLS payloads into structs that are
returned as a Gourmet Result by the tlsanalyzer. Other analyzers can depend on
this analyzer to analyze TLS payloads without having to decode the payload
themselves.
 */
package tlsresult

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type TlsType                 uint8
type TlsVersion              uint16

const (
	ApplicationDataType  TlsType = 23
	HeartbeatType        TlsType = 24

	SSL30 TlsVersion = 0
	TLS10 TlsVersion = 1
	TLS11 TlsVersion = 2
	TLS12 TlsVersion = 3
	TLS13 TlsVersion = 4
)

type TLS struct {
	ChangeCipherSpec []ChangeCipherSpecRecord
	Alert            []AlertRecord
	Handshake        []HandshakeRecord
	ApplicationData  []ApplicationDataRecord
	Heartbeat        []HeartbeatRecord
}

type TlsHeader struct {
	Type    TlsType
	Version TlsVersion
	Length  uint16
}

func (tt TlsType) String() string {
	switch tt {
	case ChangeCipherSpecType:
		return "Change Cipher Spec"
	case AlertType:
		return "Alert"
	case HandshakeType:
		return "Handshake"
	case ApplicationDataType:
		return "Application Data"
	default:
		return "Unknown"
	}
}

func (tv TlsVersion) String() string {
	switch tv {
	case 0x0200:
		return "SSL 2.0"
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func DecodeTLS(data []byte) (t *TLS, err error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("TLS record too short")
	}
	t = &TLS{}
	err = t.decodeTlsPayload(data)
	return t, err
}

func (t *TLS) decodeTlsPayload(data []byte) (err error) {
	if len(data) < 5 {
		return errors.New("TLS record too short")
	}
	var h TlsHeader
	h.Type = TlsType(data[0])
	h.Version = TlsVersion(binary.BigEndian.Uint16(data[1:3]))
	h.Length = binary.BigEndian.Uint16(data[3:5])
	hl := 5
	tl := hl + int(h.Length)

	switch h.Type {
	case ChangeCipherSpecType:
		var ccs ChangeCipherSpecRecord
		e := ccs.decodeChangeCipherSpec(data[hl:tl])
		if e != nil {
			return e
		}
		t.ChangeCipherSpec = append(t.ChangeCipherSpec, ccs)
	case AlertType:
		var a AlertRecord
		e := a.decodeAlert(data[hl:tl])
		if e != nil {
			return e
		}
		t.Alert = append(t.Alert, a)
	case HandshakeType:
		consumed := 5
		for consumed < len(data[consumed:tl]) {
			var hs HandshakeRecord
			c, e := hs.decodeHandshake(data[consumed:tl])
			if e != nil {
				return e
			}
			t.Handshake = append(t.Handshake, hs)
			consumed += c
		}
		/*
	case ApplicationDataType:
		var ad ApplicationDataRecord
		e := decodeApplicationData(data[hl:tl])
		if e != nil {
			return e
		}
		t.ApplicationData = append(t.ApplicationData, ad)
	case HeartbeatType:
		var hb HeartbeatRecord
		e := decodeHeartbeat(data[hl:tl])
		if e != nil {
			return e
		}
		t.Heartbeat = append(t.Heartbeat, hb)
		 */
	default:
		return errors.New("unknown TLS record type")
	}
	return nil
}