package net.sourceforge.pmd.lang.java.rule.security;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class SeamLogInjectionRule extends AbstractJavaRule {
    private static final List<String> LOG_LEVELS = Arrays.asList("debug", "error", "fatal", "info", "trace", "warn");
    private static final Pattern SEAM_LOG_PATTERN = Pattern.compile("org\\.jboss\\.seam\\.log\\.Log");

    public SeamLogInjectionRule() {
        definePropertyDescriptor(PropertyFactory.stringProperty("message")
                .desc("Seam Logging API supports expression language which can lead to code injection")
                .defaultValue("Seam Logging API supports an expression language that can lead to unwanted code execution. Verify the source of dynamic values.")
                .build());
    }

    @Override
    public Object visit(ASTPrimaryExpression node, Object data) {
        if (!hasSeamLogImport(node) && !isSeamLogVariable(node)) {
            return super.visit(node, data);
        }

        List<ASTPrimaryPrefix> prefixes = node.findDescendantsOfType(ASTPrimaryPrefix.class);
        for (ASTPrimaryPrefix prefix : prefixes) {
            if (prefix.jjtGetNumChildren() == 0) {
                continue;
            }

            ASTName name = prefix.getFirstDescendantOfType(ASTName.class);
            if (name != null && isLogMethodCall(name)) {
                ASTAdditiveExpression additiveExpr = node.getFirstDescendantOfType(ASTAdditiveExpression.class);
                if (additiveExpr != null) {
                    addViolation(data, node);
                }
            }
        }

        return super.visit(node, data);
    }

    private boolean hasSeamLogImport(ASTPrimaryExpression node) {
        ASTCompilationUnit compilationUnit = node.getFirstParentOfType(ASTCompilationUnit.class);
        if (compilationUnit != null) {
            for (ASTImportDeclaration importDecl : compilationUnit.findDescendantsOfType(ASTImportDeclaration.class)) {
                if (SEAM_LOG_PATTERN.matcher(importDecl.getImportedName()).matches()) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isSeamLogVariable(ASTPrimaryExpression node) {
        ASTVariableDeclaratorId varDecl = node.getFirstParentOfType(ASTVariableDeclaratorId.class);
        return varDecl != null && varDecl.getType() != null && 
               SEAM_LOG_PATTERN.matcher(varDecl.getType().getName()).matches();
    }

    private boolean isLogMethodCall(ASTName name) {
        String methodName = name.getImage();
        if (methodName.contains(".")) {
            methodName = methodName.substring(methodName.lastIndexOf('.') + 1);
        }
        return LOG_LEVELS.contains(methodName.toLowerCase());
    }
}