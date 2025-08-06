package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.ast.Node;
import java.util.Arrays;
import java.util.List;

public class SubprocessCommandInjectionRule extends AbstractJavaRule {
    private static final List<String> UNSAFE_METHODS = Arrays.asList(
        "Command",
        "CommandContext",
        "Exec", 
        "ForkExec",
        "StartProcess"
    );
    
    private static final List<String> UNSAFE_CLASSES = Arrays.asList(
        "java.lang.Runtime",
        "java.lang.ProcessBuilder",
        "java.lang.Process",
        "java.lang.UNIXProcess"
    );

    @Override
    public Object visit(ASTMethodCall node, Object data) {
        if (isUnsafeMethodCall(node)) {
            checkArgumentsForTaint(node, data);
        }
        return super.visit(node, data);
    }

    private boolean isUnsafeMethodCall(ASTMethodCall node) {
        String methodName = node.getMethodName();
        String className = getClassName(node);
        return UNSAFE_METHODS.contains(methodName) && 
               UNSAFE_CLASSES.stream().anyMatch(className::contains);
    }

    private void checkArgumentsForTaint(ASTMethodCall node, Object data) {
        List<ASTExpression> arguments = node.getArguments();
        for (ASTExpression arg : arguments) {
            if (isTaintedArgument(arg)) {
                addViolation(data, node, "Subprocess launched with potential tainted input");
            }
        }
    }

    private boolean isTaintedArgument(Node arg) {
        return arg instanceof ASTVariableAccess || 
               arg instanceof ASTMethodCall ||
               arg instanceof ASTArrayAccess;
    }

    private String getClassName(ASTMethodCall node) {
        ASTPrimaryExpression primaryExpr = node.getFirstParentOfType(ASTPrimaryExpression.class);
        if (primaryExpr != null) {
            ASTPrimaryPrefix prefix = primaryExpr.getFirstDescendantOfType(ASTPrimaryPrefix.class);
            if (prefix != null) {
                return prefix.getImage();
            }
        }
        return "";
    }
}