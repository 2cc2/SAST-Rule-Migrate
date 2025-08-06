package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type insecureTLSCipher struct {
	issue.MetaData
	ciphers []string
}

func (i *insecureTLSCipher) ID() string {
	return i.MetaData.ID
}

func (i *insecureTLSCipher) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node, ok := n.(*ast.CompositeLit); ok {
		if t, ok := node.Type.(*ast.SelectorExpr); ok {
			if t.X.(*ast.Ident).Name == "tls" {
				if t.Sel.Name == "Config" {
					for _, elem := range node.Elts {
						if kv, ok := elem.(*ast.KeyValueExpr); ok {
							if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == "CipherSuites" {
								if cl, ok := kv.Value.(*ast.CompositeLit); ok {
									for _, cipher := range cl.Elts {
										if sel, ok := cipher.(*ast.SelectorExpr); ok {
											cipherName := sel.Sel.Name
											for _, badCipher := range i.ciphers {
												if cipherName == badCipher {
													return c.NewIssue(n, i.ID(), i.What, i.Severity, i.Confidence), nil
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewInsecureTLSCipher(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	ciphers := []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	}
	return &insecureTLSCipher{
		ciphers: ciphers,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "Detected an insecure CipherSuite via the 'tls' module. This suite is considered weak. Use the function 'tls.CipherSuites()' to get a list of good cipher suites. See https://golang.org/pkg/crypto/tls/#InsecureCipherSuites for why and what other cipher suites to use. CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
		},
	}, []ast.Node{(*ast.CompositeLit)(nil)}
}