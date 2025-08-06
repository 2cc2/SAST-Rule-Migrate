package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type jwtNoneAlg struct {
	issue.MetaData
	calls gosec.CallList
}

func (j *jwtNoneAlg) ID() string {
	return j.MetaData.ID
}

func (j *jwtNoneAlg) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := j.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(n, j.ID(), j.What, j.Severity, j.Confidence), nil
	}
	return nil, nil
}

// NewJWTNoneAlg detects usage of 'none' algorithm in JWT tokens
func NewJWTNoneAlg(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("github.com/golang-jwt/jwt", "SigningMethodNone")
	calls.Add("github.com/dgrijalva/jwt-go", "SigningMethodNone")
	calls.Add("github.com/golang-jwt/jwt", "UnsafeAllowNoneSignatureType")
	calls.Add("github.com/dgrijalva/jwt-go", "UnsafeAllowNoneSignatureType")

	return &jwtNoneAlg{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.High,
			What: "Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'. CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}