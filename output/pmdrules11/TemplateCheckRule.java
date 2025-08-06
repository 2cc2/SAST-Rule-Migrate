# 转换后的 PMD 规则
package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.ASTPrimaryExpression;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryPrefix;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.java.ast.ASTArguments;
import net.sourceforge.pmd.lang.java.ast.ASTName;

public class TemplateCheckRule extends AbstractJavaRule {

    private static final String[] TEMPLATE_METHODS = {
        "html.template.CSS",
        "html.template.HTML",
        "html.template.HTMLAttr",
        "html.template.JS",
        "html.template.JSStr",
        "html.template.Srcset",
        "html.template.URL"
    };

    public TemplateCheckRule() {
        setDescription("The used method does not auto-escape HTML. This can potentially lead to Cross-site Scripting vulnerabilities, in case the attacker controls the input.");
        setMessage("Potential XSS vulnerability: found unescaped template method usage");
        setPriority(4); // MEDIUM priority
    }

    @Override
    public Object visit(ASTPrimaryExpression node, Object data) {
        ASTPrimaryPrefix prefix = node.getFirstChildOfType(ASTPrimaryPrefix.class);
        if (prefix != null) {
            ASTName name = prefix.getFirstChildOfType(ASTName.class);
            if (name != null) {
                String fullName = name.getImage();
                for (String method : TEMPLATE_METHODS) {
                    if (fullName != null && fullName.contains(method)) {
                        ASTArguments args = node.getFirstChildOfType(ASTArguments.class);
                        if (args != null && args.getArgumentCount() > 0) {
                            addViolation(data, node);
                            break;
                        }
                    }
                }
            }
        }
        return super.visit(node, data);
    }
}