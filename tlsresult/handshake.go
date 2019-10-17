package tlsresult

import (
	"encoding/binary"
	"errors"
)

type HandshakeMessageType    uint8

const (
	HandshakeType        TlsType = 22

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
)

type HandshakeRecord struct {
	Type   HandshakeMessageType
	Length uint32
	Data   []byte
}

func (h *HandshakeRecord) decodeHandshake(data []byte) (consumed int, err error) {
	if len(data) < 4 {
		return 0, errors.New("TLS Handshake record too short")
	}
	h.Type = HandshakeMessageType(data[0])
	h.Length = binary.BigEndian.Uint32(data[1:4])
	hl := 4
	tl := hl + int(h.Length)
	h.Data = data[hl:tl]
	return tl, nil
}