package rules

import (
	"go/ast"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type ottoVMRun struct {
	issue.MetaData
	calls gosec.CallList
}

func (o *ottoVMRun) ID() string {
	return o.MetaData.ID
}

func (o *ottoVMRun) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := o.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) > 0 {
			if _, ok := node.Args[0].(*ast.BasicLit); !ok {
				return c.NewIssue(n, o.ID(), o.What, o.Severity, o.Confidence), nil
			}
		}
	}
	return nil, nil
}

func NewOttoVMRun(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("github.com/robertkrimen/otto", "Run")
	return &ottoVMRun{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "Detected non-static script inside otto VM. Audit the input to 'VM.Run'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code. (CWE-94, OWASP A03:2021)",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}