package rules

import (
	"go/ast"
	"regexp"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type dangerousExecCmd struct {
	issue.MetaData
	cmdCall   gosec.CallList
	shellExpr *regexp.Regexp
}

func (d *dangerousExecCmd) ID() string {
	return d.MetaData.ID
}

func (d *dangerousExecCmd) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node, ok := n.(*ast.UnaryExpr); ok {
		if call, ok := node.X.(*ast.CallExpr); ok {
			if expr, ok := call.Fun.(*ast.SelectorExpr); ok {
				if d.cmdCall.Contains("os/exec", expr.Sel.Name) {
					for _, arg := range call.Args {
						switch argType := arg.(type) {
						case *ast.BasicLit:
							continue
						case *ast.SelectorExpr:
							return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
						case *ast.Ident:
							if argType.Obj != nil && argType.Obj.Kind == ast.Var {
								return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
							}
						case *ast.CallExpr:
							if selector, ok := argType.Fun.(*ast.SelectorExpr); ok {
								if selector.Sel.Name == "LookPath" {
									continue
								}
							}
							return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
						}
					}
				}
			}
		}
	}

	if node, ok := n.(*ast.CompositeLit); ok {
		if t, ok := node.Type.(*ast.SelectorExpr); ok {
			if t.Sel.Name == "Cmd" {
				for _, elt := range node.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if ident, ok := kv.Key.(*ast.Ident); ok {
							if ident.Name == "Path" || ident.Name == "Args" {
								switch val := kv.Value.(type) {
								case *ast.BasicLit:
									continue
								case *ast.Ident:
									if val.Obj != nil && val.Obj.Kind == ast.Var {
										return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
									}
								case *ast.CallExpr:
									if selector, ok := val.Fun.(*ast.SelectorExpr); ok {
										if selector.Sel.Name == "LookPath" {
											continue
										}
									}
									return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

// NewDangerousExecCmd creates a rule to detect non-static commands in exec.Cmd
func NewDangerousExecCmd(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	shellPattern := regexp.MustCompile("(sh|bash|ksh|csh|tcsh|zsh)")

	callList := gosec.NewCallList()
	callList.Add("os/exec", "Command")
	callList.Add("os/exec", "CommandContext")

	return &dangerousExecCmd{
		cmdCall: callList,
		shellExpr: shellPattern,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Medium,
			What:       "Detected non-static command inside exec.Cmd. Audit the input to 'exec.Cmd'. If unverified user data can reach this call site, this is a code injection vulnerability.",
		},
	}, []ast.Node{(*ast.UnaryExpr)(nil), (*ast.CompositeLit)(nil)}
}