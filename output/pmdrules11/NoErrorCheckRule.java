package com.example.pmdrules;

import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.java.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.java.ast.ASTExpressionStatement;
import net.sourceforge.pmd.lang.java.ast.ASTMethodCall;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.java.types.TypeTestUtil;
import net.sourceforge.pmd.lang.rule.RuleContext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class NoErrorCheckRule extends AbstractJavaRule {
    private static final List<String> WHITELIST_PACKAGES = Arrays.asList(
        "bytes.Buffer", "fmt", "strings.Builder", "io.PipeWriter", "hash.Hash", "os"
    );
    private static final List<String> WHITELIST_METHODS = Arrays.asList(
        "Write", "WriteByte", "WriteRune", "WriteString",
        "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln",
        "CloseWithError", "Unsetenv"
    );

    @Override
    public Object visit(ASTAssignmentExpression node, Object data) {
        RuleContext ctx = (RuleContext) data;
        
        // Check if audit is enabled (assuming PMD has similar config)
        if (!isRuleEnabled(ctx)) {
            return super.visit(node, data);
        }

        List<ASTMethodCall> methodCalls = node.findDescendantsOfType(ASTMethodCall.class);
        for (ASTMethodCall call : methodCalls) {
            if (!isWhitelisted(call) && returnsError(call)) {
                if (isErrorIgnored(node)) {
                    addViolation(ctx, node);
                }
            }
        }

        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTExpressionStatement node, Object data) {
        RuleContext ctx = (RuleContext) data;
        
        ASTMethodCall call = node.getFirstDescendantOfType(ASTMethodCall.class);
        if (call != null && !isWhitelisted(call) && returnsError(call)) {
            addViolation(ctx, node);
        }

        return super.visit(node, data);
    }

    private boolean isRuleEnabled(RuleContext ctx) {
        // PMD rules are typically always enabled when registered
        return true;
    }

    private boolean isWhitelisted(ASTMethodCall call) {
        String methodName = call.getMethodName();
        String className = call.getQualifier() != null ? call.getQualifier().toString() : "";
        
        return WHITELIST_METHODS.contains(methodName) || 
               WHITELIST_PACKAGES.stream().anyMatch(pkg -> className.startsWith(pkg));
    }

    private boolean returnsError(ASTMethodCall call) {
        // In PMD, we'd typically use TypeTestUtil to check return type
        return TypeTestUtil.isA("java.lang.Exception", call);
    }

    private boolean isErrorIgnored(ASTAssignmentExpression assign) {
        // Check if assignment target is underscore (ignored in Go) or null check in Java
        // This is a simplified version - need more complex analysis for Java
        return assign.getChildren().stream()
            .anyMatch(n -> n.toString().equals("_"));
    }
}