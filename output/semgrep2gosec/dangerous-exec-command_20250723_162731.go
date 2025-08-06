package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type execCommand struct {
	issue.MetaData
	calls gosec.CallList
}

func (e *execCommand) ID() string {
	return e.MetaData.ID
}

func (e *execCommand) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := e.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		for _, arg := range node.Args {
			if _, ok := arg.(*ast.BasicLit); !ok {
				return c.NewIssue(n, e.ID(), e.What, e.Severity, e.Confidence), nil
			}
		}
	}
	return nil, nil
}

// NewExecCommand creates a rule to detect non-static commands in exec.Command calls
func NewExecCommand(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("os/exec", "Command")
	calls.Add("os/exec", "CommandContext")
	return &execCommand{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}