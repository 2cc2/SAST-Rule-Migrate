// 转换后的 Gosec 规则

package rules

import (
	"go/ast"
	"go/types"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

// httpDirTraversalRule 检测是否存在对 http.Dir($ARG) 的调用，提示潜在的目录穿越风险
type httpDirTraversalRule struct {
	issue.MetaData
	calls gosec.CallList
}

func (r *httpDirTraversalRule) ID() string {
	return r.MetaData.ID
}

func (r *httpDirTraversalRule) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// 检查是否是 http.Dir 调用
	if ce := r.calls.ContainsPkgCallExpr(n, c, false); ce != nil {
		// 进一步确认是否是 http.Dir
		if sel, ok := ce.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				// 确保调用方是 "http" 包
				if obj := c.Info.ObjectOf(ident); obj != nil {
					if named, ok := obj.Type().(*types.Package); ok {
						if named.Path() == "net/http" || named.Name() == "http" {
							return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
						}
					}
				} else if ident.Name == "http" {
					// fallback 情况：无法解析类型，但名称匹配
					return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

// NewHttpDirTraversalRule 构建 Gosec 自定义规则：检测 http.Dir 调用
func NewHttpDirTraversalRule(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("http", "Dir")

	return &httpDirTraversalRule{
		MetaData: issue.MetaData{
			ID:         id,
			What:       "Potential directory traversal via http.Dir",
			Severity:   issue.Medium,
			Confidence: issue.Medium,
		},
		calls: calls,
	}, []ast.Node{(*ast.CallExpr)(nil)}
}