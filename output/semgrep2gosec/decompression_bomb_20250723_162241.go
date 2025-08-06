package rules

import (
	"go/ast"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type decompressionBomb struct {
	issue.MetaData
	decompressionFuncs gosec.CallList
	copyFuncs          gosec.CallList
}

func (d *decompressionBomb) ID() string {
	return d.MetaData.ID
}

func (d *decompressionBomb) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := d.decompressionFuncs.ContainsPkgCallExpr(n, c, false); node != nil {
		if copyNode, ok := n.(*ast.CallExpr); ok {
			if sel, ok := copyNode.Fun.(*ast.SelectorExpr); ok {
				if d.copyFuncs.Contains("io", sel.Sel.Name) {
					return c.NewIssue(n, d.ID(), d.What, d.Severity, d.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

func NewDecompressionBomb(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	decompression := gosec.NewCallList()
	decompression.Add("compress/gzip", "NewReader")
	decompression.Add("compress/zlib", "NewReader")
	decompression.Add("compress/zlib", "NewReaderDict")
	decompression.Add("compress/bzip2", "NewReader")
	decompression.Add("compress/flate", "NewReader")
	decompression.Add("compress/flate", "NewReaderDict")
	decompression.Add("compress/lzw", "NewReader")
	decompression.Add("archive/tar", "NewReader")
	decompression.Add("archive/zip", "NewReader")
	decompression.Add("archive/zip", "OpenReader")

	copyFuncs := gosec.NewCallList()
	copyFuncs.Add("io", "Copy")
	copyFuncs.Add("io", "CopyBuffer")

	return &decompressionBomb{
		decompressionFuncs: decompression,
		copyFuncs:          copyFuncs,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Low,
			What:       "Potential DoS via decompression bomb. Use io.CopyN with size limit to mitigate. References: https://golang.org/pkg/io/#CopyN, CWE-400: Uncontrolled Resource Consumption",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}