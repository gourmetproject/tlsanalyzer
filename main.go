package main

import (
	"github.com/gourmetproject/gourmet"
	"github.com/gourmetproject/tlsanalyzer/tlsresult"
)

type Tls []interface{}

func (t Tls) Key() string {
	return "tls"
}

type TlsAnalyzer struct{}

func NewAnalyzer() gourmet.Analyzer {
	return &TlsAnalyzer{}
}

func (ta *TlsAnalyzer) Filter(c *gourmet.Connection) bool {
	return c.SourcePort == 443 || c.DestinationPort == 443
}

func (ta *TlsAnalyzer) Analyze(c *gourmet.Connection) (gourmet.Result, error) {
	result, err := tlsresult.DecodeTlsPayload(c.Payload.Bytes())
	return Tls(result), err
}