# 转换后的 PMD 规则
package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.*;
import net.sourceforge.pmd.*;

public class UsesWeakCryptographyHashRule extends AbstractJavaRule {

    private static final String[] MD5_METHODS = {"New", "Sum"};
    private static final String[] SHA1_METHODS = {"New", "Sum"};

    public UsesWeakCryptographyHashRule() {
        setProperty(PropertyDescriptor.severity, Severity.MEDIUM);
        setMessage("Use of weak cryptographic primitive");
    }

    @Override
    public Object visit(ASTMethodCall node, Object data) {
        ASTName name = node.getFirstChildOfType(ASTName.class);
        if (name != null && name.getImage() != null) {
            String fullName = name.getImage();
            if (fullName.contains("md5")) {
                checkMethods(node, data, MD5_METHODS);
            } else if (fullName.contains("sha1")) {
                checkMethods(node, data, SHA1_METHODS);
            }
        }
        return super.visit(node, data);
    }

    private void checkMethods(ASTMethodCall node, Object data, String[] methods) {
        String methodName = node.getMethodName();
        for (String method : methods) {
            if (method.equals(methodName)) {
                addViolation(data, node);
                break;
            }
        }
    }
}