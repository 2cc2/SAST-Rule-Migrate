package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type gormDangerousMethod struct {
	issue.MetaData
	gormCall   gosec.CallList
	dangerous  []string
	httpFields []string
}

func (g *gormDangerousMethod) ID() string {
	return g.MetaData.ID
}

func (g *gormDangerousMethod) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if node := g.gormCall.ContainsPkgCallExpr(n, c, false); node != nil {
		for _, method := range g.dangerous {
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == method {
					for _, arg := range node.Args {
						// Check if the argument comes from http.Request
						if ident, ok := arg.(*ast.Ident); ok && ident.Obj != nil {
							if decl, ok := ident.Obj.Decl.(*ast.Field); ok {
								if fieldType, ok := decl.Type.(*ast.SelectorExpr); ok {
									if x, ok := fieldType.X.(*ast.Ident); ok && (x.Name == "http" || x.Name == "Request") {
										for _, field := range g.httpFields {
											if fieldType.Sel.Name == field {
												return c.NewIssue(n, g.ID(), g.What, g.Severity, g.Confidence), nil
											}
										}
									}
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

func NewGormDangerousMethod(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	gormCall := gosec.NewCallList()
	gormCall.Add("gorm.io/gorm", "DB")
	dangerousMethods := []string{"Order", "Exec", "Raw", "Group", "Having", "Distinct", "Select", "Pluck"}
	httpFields := []string{"BasicAuth", "Body", "Cookie", "Cookies", "Form", "FormValue", "GetBody", "Host", 
		"MultipartReader", "ParseForm", "ParseMultipartForm", "PostForm", "PostFormValue", "Referer", 
		"RequestURI", "Trailer", "TransferEncoding", "UserAgent", "URL"}

	return &gormDangerousMethod{
		gormCall:   gormCall,
		dangerous:  dangerousMethods,
		httpFields: httpFields,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "Detected usage of dangerous GORM method which does not escape inputs. If the argument is user-controlled, this can lead to SQL injection. When using these methods, do not trust user-submitted data and only allow approved list of input (CWE-89, OWASP A01:2017, OWASP A03:2021). See references: https://gorm.io/docs/security.html#SQL-injection-Methods, https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}