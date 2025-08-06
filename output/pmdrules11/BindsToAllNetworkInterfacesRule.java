package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.ASTLiteral;
import net.sourceforge.pmd.lang.java.ast.ASTMethodCall;
import net.sourceforge.pmd.lang.java.ast.ASTName;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.java.types.TypeTestUtil;
import net.sourceforge.pmd.lang.ast.Node;

import java.util.regex.Pattern;

public class BindsToAllNetworkInterfacesRule extends AbstractJavaRule {
    private static final Pattern BIND_PATTERN = Pattern.compile("^(0\\.0\\.0\\.0|:).*$");
    
    public BindsToAllNetworkInterfacesRule() {
        addRuleChainVisit(ASTMethodCall.class);
    }

    @Override
    public Object visit(ASTMethodCall call, Object data) {
        if (isListenCall(call)) {
            checkNetworkBinding(call, data);
        }
        return super.visit(call, data);
    }

    private boolean isListenCall(ASTMethodCall call) {
        ASTName methodName = call.getFirstChildOfType(ASTName.class);
        if (methodName == null) {
            return false;
        }
        String name = methodName.getImage();
        return "Listen".equals(name) && 
              (TypeTestUtil.isA("net", call) || TypeTestUtil.isA("crypto.tls", call));
    }

    private void checkNetworkBinding(ASTMethodCall call, Object data) {
        if (call.getArguments().size() < 1) {
            return;
        }
        
        Node arg = call.getArgument(0);
        if (arg instanceof ASTLiteral) {
            String value = ((ASTLiteral)arg).getImage();
            if (value != null && BIND_PATTERN.matcher(value).matches()) {
                addViolation(data, call);
            }
        }
    }
}