package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type responseWriterFprintf struct {
	issue.MetaData
	calls gosec.CallList
}

func (r *responseWriterFprintf) ID() string {
	return r.MetaData.ID
}

func (r *responseWriterFprintf) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := r.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 0 {
			firstArg := node.Args[0]
			if ident, ok := firstArg.(*ast.Ident); ok {
				if ident.Obj != nil {
					if typ := c.Info.TypeOf(ident); typ != nil {
						if typ.String() == "http.ResponseWriter" {
							return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewResponseWriterFprintf(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("fmt", "Fprintf")
	calls.Add("fmt", "Fprint")
	calls.Add("fmt", "Fprintln")
	return &responseWriterFprintf{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "Detected 'Fprintf' or similar writing to 'http.ResponseWriter'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package to render data to users. OWASP: A07:2017, A03:2021. CWE: CWE-79",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}