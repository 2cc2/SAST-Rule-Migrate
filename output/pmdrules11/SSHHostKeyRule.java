package com.example.pmdrules;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;

public class SSHHostKeyRule extends AbstractJavaRule {
    private static final String TARGET_PACKAGE = "golang.org.x.crypto.ssh";
    private static final String TARGET_METHOD = "InsecureIgnoreHostKey";

    public SSHHostKeyRule() {
        setMessage("Use of ssh InsecureIgnoreHostKey should be audited");
        setPriority(Priority.MEDIUM);
    }

    @Override
    public Object visit(ASTMethodCall node, RuleContext ctx) {
        checkMethodCall(node, ctx);
        return super.visit(node, ctx);
    }

    private void checkMethodCall(ASTMethodCall node, RuleContext ctx) {
        try {
            ASTPrimaryExpression expr = node.getFirstChildOfType(ASTPrimaryExpression.class);
            if (expr != null) {
                ASTPrimaryPrefix prefix = expr.getFirstChildOfType(ASTPrimaryPrefix.class);
                if (prefix != null) {
                    ASTName name = prefix.getFirstDescendantOfType(ASTName.class);
                    if (name != null && name.getImage() != null) {
                        String fullName = name.getImage();
                        if (fullName.startsWith(TARGET_PACKAGE) && 
                            fullName.endsWith("." + TARGET_METHOD)) {
                            addViolation(ctx, node);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Log error if needed
        }
    }
}