package rules

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type htmlFormat struct {
	issue.MetaData
	fmtCalls gosec.CallList
	httpReq  *types.Interface
}

func (h *htmlFormat) ID() string {
	return h.MetaData.ID
}

// Match inspects AST nodes to detect user input flowing into manually constructed HTML strings
func (h *htmlFormat) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Check for request sources
	if ident, ok := n.(*ast.Ident); ok {
		if ident.Obj != nil {
			if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
				if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" {
							return c.NewIssue(n, h.ID(), h.What, h.Severity, h.Confidence), nil
						}
					}
				}
			}
		}
	}

	// Check for fmt.* sink calls
	if node := h.fmtCalls.ContainsPkgCallExpr(n, c, false); node != nil {
		if basicLit, ok := node.Args[0].(*ast.BasicLit); ok && basicLit.Kind == token.STRING {
			if strings.Contains(basicLit.Value, "<") {
				return c.NewIssue(n, h.ID(), h.What, h.Severity, h.Confidence), nil
			}
		}
	}
	return nil, nil
}

// NewHTMLFormat creates a rule to detect XSS vulnerabilities from manually constructed HTML
func NewHTMLFormat(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("fmt", "Printf")
	calls.Add("fmt", "Sprintf")
	calls.Add("fmt", "Fprintf")

	return &htmlFormat{
		fmtCalls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What: "Detected user input flowing into manually constructed HTML string which may cause XSS. " +
				"Use html/template package instead. CWE-79, OWASP A07:2017/A03:2021",
		},
	}, []ast.Node{(*ast.Ident)(nil), (*ast.CallExpr)(nil)}
}