package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type tlsMinVersion struct {
	issue.MetaData
	configs gosec.CallList
}

func (t *tlsMinVersion) ID() string {
	return t.MetaData.ID
}

func (t *tlsMinVersion) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node, ok := n.(*ast.CompositeLit); ok {
		if ident, ok := node.Type.(*ast.Ident); ok && ident.Name == "Config" {
			// Check if it's tls.Config
			if selExpr, ok := ident.Obj.Decl.(*ast.TypeSpec).Type.(*ast.SelectorExpr); ok {
				if xIdent, ok := selExpr.X.(*ast.Ident); ok && xIdent.Name == "tls" {
					// Check for missing MinVersion field
					hasMinVersion := false
					for _, elt := range node.Elts {
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "MinVersion" {
								hasMinVersion = true
								break
							}
						}
					}
					if !hasMinVersion {
						return c.NewIssue(node, t.ID(), t.What, t.Severity, t.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func NewTLSMinVersion(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &tlsMinVersion{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "`MinVersion` is missing from this TLS configuration. By default, TLS 1.2 is currently used as the minimum when acting as a client, and TLS 1.0 when acting as a server. General purpose web applications should default to TLS 1.3 with all other protocols disabled. Only where it is known that a web server must support legacy clients with unsupported an insecure browsers (such as Internet Explorer 10), it may be necessary to enable TLS 1.0 to provide support. Add `MinVersion: tls.VersionTLS13' to the TLS configuration to bump the minimum version to TLS 1.3.",
		},
	}, []ast.Node{(*ast.CompositeLit)(nil)}
}