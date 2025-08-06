package rules

import (
	"go/ast"
	"regexp"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type md5Password struct {
	issue.MetaData
	md5Calls gosec.CallList
	passwordPattern *regexp.Regexp
}

func (m *md5Password) ID() string {
	return m.MetaData.ID
}

func (m *md5Password) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := m.md5Calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if ident, ok := callExpr.Fun.(*ast.Ident); ok {
				if m.passwordPattern.MatchString(ident.Name) {
					return c.NewIssue(n, m.ID(), m.What, m.Severity, m.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewMd5Password(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	md5Calls := gosec.NewCallList()
	md5Calls.Add("crypto/md5", "New")
	md5Calls.Add("crypto/md5", "Sum")

	pattern := regexp.MustCompile(`(?i).*password.*`)

	return &md5Password{
		md5Calls: md5Calls,
		passwordPattern: pattern,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Use of MD5 for password hashing detected. MD5 is not secure for this purpose. Use golang.org/x/crypto/bcrypt package instead. See references: https://tools.ietf.org/id/draft-lvelvindron-tls-md5-sha1-deprecate-01.html, https://security.stackexchange.com/questions/211/how-to-securely-hash-passwords",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}