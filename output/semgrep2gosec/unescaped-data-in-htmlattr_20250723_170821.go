package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type htmlAttrCheck struct {
	issue.MetaData
	calls gosec.CallList
}

func (h *htmlAttrCheck) ID() string {
	return h.MetaData.ID
}

func (h *htmlAttrCheck) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := h.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		for _, arg := range node.Args {
			if _, ok := arg.(*ast.BinaryExpr); ok { // Check for string concatenation
				return c.NewIssue(n, h.ID(), h.What, h.Severity, h.Confidence), nil
			}
			if call, ok := arg.(*ast.CallExpr); ok { // Check for fmt.Sprintf etc
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "fmt" {
						return c.NewIssue(n, h.ID(), h.What, h.Severity, h.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func NewHTMLAttrCheck(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("html/template", "HTMLAttr")
	return &htmlAttrCheck{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "Found unescaped data in template.HTMLAttr(). Be absolutely sure there is no user-controlled data in this template or validate and sanitize the data first. CWE: CWE-79. OWASP: A07:2017 - Cross-Site Scripting (XSS), A03:2021 - Injection",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}