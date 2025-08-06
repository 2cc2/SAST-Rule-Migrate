package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type insecureSessionCookie struct {
	issue.MetaData
	optionsType string
}

func (i *insecureSessionCookie) ID() string {
	return i.MetaData.ID
}

func (i *insecureSessionCookie) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if compLit, ok := n.(*ast.CompositeLit); ok {
		if selExpr, ok := compLit.Type.(*ast.SelectorExpr); ok {
			if ident, ok := selExpr.X.(*ast.Ident); ok && ident.Name == "sessions" && selExpr.Sel.Name == "Options" {
				secureFound := false
				for _, elt := range compLit.Elts {
					if kvExpr, ok := elt.(*ast.KeyValueExpr); ok {
						if key, ok := kvExpr.Key.(*ast.Ident); ok && key.Name == "Secure" {
							if val, ok := kvExpr.Value.(*ast.Ident); ok && val.Name == "true" {
								secureFound = true
								break
							}
						}
					}
				}
				if !secureFound {
					return c.NewIssue(n, i.ID(), i.What, i.Severity, i.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewInsecureSessionCookie(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &insecureSessionCookie{
		optionsType: "github.com/gorilla/sessions.Options",
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "A session cookie was detected without setting the 'Secure' flag (CWE-614). The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP.",
		},
	}, []ast.Node{(*ast.CompositeLit)(nil)}
}