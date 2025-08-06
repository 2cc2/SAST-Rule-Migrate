package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.ASTConstructorCall;
import net.sourceforge.pmd.lang.java.ast.ASTExpression;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.java.ast.ASTArgumentList;
import net.sourceforge.pmd.lang.java.ast.ASTMemberValuePair;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import static net.sourceforge.pmd.properties.PropertyDescriptorField.*;

public class SlowlorisRule extends AbstractJavaRule {
    private static final String HTTP_SERVER = "http.Server";
    
    public SlowlorisRule() {
        definePropertyDescriptor(PropertyDescriptor.<String>build()
                .name("violationSuppressRegex")
                .desc("Potential Slowloris Attack because ReadHeaderTimeout is not configured in the http.Server"));
        definePropertyDescriptor(PropertyDescriptor.<Integer>build()
                .name("confidence")
                .range(1, 5)
                .value(2)); // LOW=2
        definePropertyDescriptor(PropertyDescriptor.<Integer>build()
                .name("severity")
                .range(1, 5)
                .value(3)); // MEDIUM=3
    }
    
    @Override
    public Object visit(ASTConstructorCall node, Object data) {
        String typeName = node.getTypeName();
        if (HTTP_SERVER.equals(typeName)) {
            boolean hasTimeout = checkTimeoutConfiguration(node.getFirstChildOfType(ASTArgumentList.class));
            if (!hasTimeout) {
                addViolation(data, node);
            }
        }
        return super.visit(node, data);
    }
    
    private boolean checkTimeoutConfiguration(ASTArgumentList args) {
        if (args == null) {
            return false;
        }
        
        for (ASTExpression expr : args.findChildrenOfType(ASTExpression.class)) {
            if (expr instanceof ASTMemberValuePair) {
                String propName = ((ASTMemberValuePair) expr).getName();
                if ("ReadHeaderTimeout".equals(propName) || "ReadTimeout".equals(propName)) {
                    return true;
                }
            }
        }
        return false;
    }
}