/*
修改策略：
1. 移除文件开头的非法字符
2. 保持原有功能逻辑不变
3. 确保代码符合 Go 语言语法规范
*/

package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type insecureModule struct {
	issue.MetaData
	imports *ast.GenDecl
	calls   gosec.CallList
}

func (i *insecureModule) ID() string {
	return i.MetaData.ID
}

func (i *insecureModule) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node, ok := n.(*ast.ImportSpec); ok {
		if node.Path != nil && node.Path.Value == "\"net/http/cgi\"" {
			return c.NewIssue(node, i.ID(), i.What, i.Severity, i.Confidence), nil
		}
	}

	if node := i.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return c.NewIssue(node, i.ID(), i.What, i.Severity, i.Confidence), nil
	}
	return nil, nil
}

func NewInsecureModule(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("net/http/cgi", "...")
	return &insecureModule{
		calls: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "The package `net/http/cgi` is on the import blocklist. The package is vulnerable to httpoxy attacks (CVE-2015-5386). It is recommended to use `net/http` or a web framework to build a web application instead.",
		},
	}, []ast.Node{(*ast.ImportSpec)(nil), (*ast.CallExpr)(nil)}
}