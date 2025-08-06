package rules

import (
	"go/ast"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type templateInterpolation struct {
	issue.MetaData
}

func (t *templateInterpolation) ID() string {
	return t.MetaData.ID
}

func (t *templateInterpolation) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if lit, ok := n.(*ast.BasicLit); ok && strings.Contains(lit.Value, "<{{") {
		return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence), nil
	}
	return nil, nil
}

// NewTemplateInterpolation creates a rule to detect template variable interpolation in HTML tags
func NewTemplateInterpolation(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &templateInterpolation{
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What: "Detected template variable interpolation in an HTML tag. This is potentially vulnerable to XSS " +
				"attacks because a malicious actor has control over HTML without needing escaped characters. " +
				"Use explicit tags instead. CWE-79, OWASP A07:2017/A03:2021.",
		},
	}, []ast.Node{(*ast.BasicLit)(nil)}
}