package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type printfInResponseWriter struct {
	issue.MetaData
	writer   gosec.CallList
	printf   gosec.CallList
}

func (p *printfInResponseWriter) ID() string {
	return p.MetaData.ID
}

func (p *printfInResponseWriter) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := p.writer.ContainsCallExpr(n, c); node != nil {
		if arg, ok := node.Args[0].(*ast.CallExpr); ok {
			if sel, ok := arg.Fun.(*ast.SelectorExpr); ok {
				if p.printf.Contains(sel.X.(*ast.Ident).Name, sel.Sel.Name) {
					return c.NewIssue(n, p.ID(), p.What, p.Severity, p.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewPrintfInResponseWriter(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	writer := gosec.NewCallList()
	writer.Add("net/http", "ResponseWriter.Write")

	printf := gosec.NewCallList()
	printf.Add("fmt", "Printf")
	printf.Add("fmt", "Sprintf")
	printf.Add("fmt", "Fprintf")

	return &printfInResponseWriter{
		writer: writer,
		printf: printf,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "Detected 'printf' or similar in 'http.ResponseWriter.write()'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package to render data to users.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}