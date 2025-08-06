package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.*;
import java.util.List;
import java.util.Set;

public class SSRFCheckRule extends AbstractJavaRule {

    private static final Set<String> HTTP_METHODS = Set.of(
        "Do", "Get", "Head", "Post", "PostForm", "RoundTrip"
    );

    @Override
    public Object visit(ASTMethodCall node, Object data) {
        if (isHttpCall(node) && isVariableArgument(node)) {
            addViolation(data, node);
        }
        return super.visit(node, data);
    }

    private boolean isHttpCall(ASTMethodCall node) {
        return node.getMethodName() != null 
            && HTTP_METHODS.contains(node.getMethodName())
            && node.getQualifiedName().startsWith("net.http.");
    }

    private boolean isVariableArgument(ASTMethodCall node) {
        List<ASTExpression> args = node.getArguments();
        if (!args.isEmpty()) {
            ASTExpression firstArg = args.get(0);
            return firstArg.descendants(ASTName.class).nonEmpty();
        }
        return false;
    }
}