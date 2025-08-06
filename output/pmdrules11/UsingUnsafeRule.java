【修改策略】
1. 移除所有非法Unicode字符（中文标点和特殊符号）
2. 替换非标准注释标记为Java标准注释(//或/* */)
3. 确保类声明完整规范
4. 修正priority设置方式，使用PMD标准的优先级数值(4对应LOW级别)
5. 添加null检查避免潜在NPE
6. 确保所有语法结构完整闭合（括号、分号等）
7. 验证所有导入包存在且正确

# 转换后的 PMD 规则
package com.example.pmdrules;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.ast.AbstractJavaNode;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryExpression;
import net.sourceforge.pmd.lang.java.ast.ASTName;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.java.ast.JavaNode;

public class UsingUnsafeRule extends AbstractJavaRule {
    private static final String UNSAFE_PKG = "unsafe";
    private static final String[] UNSAFE_METHODS = {"Pointer", "String", "StringData", "Slice", "SliceData"};

    public UsingUnsafeRule() {
        setRuleId("UsingUnsafe");
        setDescription("Use of unsafe calls should be audited");
        setPriority(4); // LOW priority in PMD is 4
    }

    @Override
    public Object visit(ASTPrimaryExpression node, Object data) {
        if (isUnsafeCall(node)) {
            RuleContext ctx = (RuleContext) data;
            ctx.addViolation(node, this);
        }
        return super.visit(node, data);
    }

    private boolean isUnsafeCall(ASTPrimaryExpression node) {
        if (node.jjtGetNumChildren() > 0) {
            JavaNode firstChild = (JavaNode) node.jjtGetChild(0);
            if (firstChild instanceof ASTName) {
                ASTName nameNode = (ASTName) firstChild;
                String name = nameNode.getImage();
                if (name != null && name.startsWith(UNSAFE_PKG + ".")) {
                    for (String method : UNSAFE_METHODS) {
                        if (name.endsWith("." + method)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}