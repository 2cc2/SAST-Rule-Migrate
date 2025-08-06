package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type directResponseWrite struct {
	issue.MetaData
	writerType string
	calls      gosec.CallList
}

func (d *directResponseWrite) ID() string {
	return d.MetaData.ID
}

func (d *directResponseWrite) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := d.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if rcvr, ok := node.Args[0].(*ast.Ident); ok {
			obj := rcvr.Obj
			if obj != nil {
				if decl, ok := obj.Decl.(*ast.ValueSpec); ok {
					if typ, ok := decl.Type.(*ast.Ident); ok && typ.Name == d.writerType {
						return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
					}
					if star, ok := decl.Type.(*ast.StarExpr); ok {
						if sel, ok := star.X.(*ast.SelectorExpr); ok {
							if x, ok := sel.X.(*ast.Ident); ok && x.Name == "http" && sel.Sel.Name == "ResponseWriter" {
								return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewDirectResponseWrite(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("", "Write")
	return &directResponseWrite{
		calls:      calls,
		writerType: "http.ResponseWriter",
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "Detected directly writing or similar in 'http.ResponseWriter.write()'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package and render data using 'template.Execute()'.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}