package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type textTemplateImport struct {
	issue.MetaData
	patterns []string
}

func (t *textTemplateImport) ID() string {
	return t.MetaData.ID
}

func (t *textTemplateImport) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node, ok := n.(*ast.ImportSpec); ok {
		if node.Path != nil && node.Path.Value == `"text/template"` {
			return c.NewIssue(node, t.ID(), t.What, t.Severity, t.Confidence), nil
		}
	}
	return nil, nil
}

func NewTextTemplateImport(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &textTemplateImport{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Low,
			Confidence: issue.Low,
			What:       "Using text/template package can lead to XSS vulnerabilities. Use html/template instead for automatic HTML escaping to prevent Cross-Site Scripting (XSS) attacks (OWASP A07:2017, A03:2021, CWE-79). References: https://www.veracode.com/blog/secure-development/use-golang-these-mistakes-could-compromise-your-apps-security",
		},
	}, []ast.Node{(*ast.ImportSpec)(nil)}
}