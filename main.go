package main

import (
	"github.com/gourmetproject/gourmet"
	"github.com/gourmetproject/tlsanalyzer/tlsresult"
	"log"
)

type TlsResult tlsresult.TLS

func (t TlsResult) Key() string {
	return "tls"
}

type TlsAnalyzer struct{}

func NewAnalyzer() gourmet.Analyzer {
	return &TlsAnalyzer{}
}

func (ta *TlsAnalyzer) Filter(c *gourmet.Connection) bool {
	return (c.SourcePort == 443 || c.DestinationPort == 443) &&
		len(c.Payload.Bytes()) > 0
}

func (ta *TlsAnalyzer) Analyze(c *gourmet.Connection) (gourmet.Result, error) {
	result, err := tlsresult.DecodeTLS(c.Payload.Bytes())
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return TlsResult(*result), err
}