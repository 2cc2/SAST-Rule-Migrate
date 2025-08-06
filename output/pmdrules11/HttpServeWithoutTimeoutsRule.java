package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.ASTCallExpression;
import net.sourceforge.pmd.lang.java.ast.ASTName;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;

public class HttpServeWithoutTimeoutsRule extends AbstractJavaRule {
    private static final String[] TARGET_METHODS = {"ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS"};
    private static final String TARGET_PACKAGE = "net/http";

    @Override
    public Object visit(ASTCallExpression node, Object data) {
        if (isTargetMethodCall(node)) {
            addViolation(data, node, "Use of net/http serve function that has no support for setting timeouts");
        }
        return super.visit(node, data);
    }

    private boolean isTargetMethodCall(ASTCallExpression call) {
        ASTName methodName = call.getFirstChildOfType(ASTName.class);
        if (methodName != null) {
            String fullName = methodName.getImage();
            if (fullName != null && fullName.startsWith(TARGET_PACKAGE + ".")) {
                for (String targetMethod : TARGET_METHODS) {
                    if (fullName.endsWith("." + targetMethod)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}