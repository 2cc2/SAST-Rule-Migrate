package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type jwtUnverifiedParse struct {
	issue.MetaData
	calls gosec.CallList
}

func (j *jwtUnverifiedParse) ID() string {
	return j.MetaData.ID
}

func (j *jwtUnverifiedParse) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := j.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, j.ID(), j.What, j.Severity, j.Confidence), nil
	}
	return nil, nil
}

func NewJWTUnverifiedParse(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("github.com/dgrijalva/jwt-go", "ParseUnverified")
	return &jwtUnverifiedParse{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What: "Detected the decoding of a JWT token without a verify step. " +
				"Don't use `ParseUnverified` unless you know what you're doing. " +
				"This method parses the token but doesn't validate the signature. " +
				"Reference: https://semgrep.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}