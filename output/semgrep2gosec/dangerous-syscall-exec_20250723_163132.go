package rules

import (
	"go/ast"
	"regexp"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type dangerousSyscallExec struct {
	issue.MetaData
	calls gosec.CallList
	shellRegex *regexp.Regexp
}

func (d *dangerousSyscallExec) ID() string {
	return d.MetaData.ID
}

func (d *dangerousSyscallExec) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := d.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		// Check for syscall.Exec/BIN with non-static arguments
		if len(node.Args) > 0 {
			// Case 1: Check for non-string literal as first argument
			if _, ok := node.Args[0].(*ast.BasicLit); !ok {
				return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
			}

			// Case 2: Check for shell in arguments
			if len(node.Args) > 1 {
				if args, ok := node.Args[1].(*ast.CompositeLit); ok {
					for _, elt := range args.Elts {
						if lit, ok := elt.(*ast.BasicLit); ok && d.shellRegex.MatchString(lit.Value) {
							return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func NewDangerousSyscallExec(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("syscall", "Exec")
	calls.Add("syscall", "ForkExec")
	shellRegex := regexp.MustCompile(`(sh|bash|ksh|csh|tcsh|zsh)`)

	return &dangerousSyscallExec{
		calls: calls,
		shellRegex: shellRegex,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Low,
			What:       "Detected non-static command inside Exec. Audit the input to 'syscall.Exec'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}