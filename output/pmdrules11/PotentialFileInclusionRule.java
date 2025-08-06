package com.example.pmdrules;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.java.symbols.JVariableSymbol;
import java.util.HashMap;
import java.util.Map;

public class PotentialFileInclusionRule extends AbstractJavaRule {
    
    private static final String[] PATH_JOIN_METHODS = {
        "filepath.Join",
        "path.Path.join"
    };

    private static final String[] CLEAN_METHODS = {
        "filepath.Clean",
        "filepath.Rel",
        "filepath.EvalSymlinks"
    };

    private static final String[] TARGET_METHODS = {
        "io.ReadFile",
        "os.ReadFile",
        "os.Open",
        "os.OpenFile",
        "os.Create"
    };

    private final Map<ASTVariableDeclaratorId, ASTMethodCall> cleanedVariables = new HashMap<>();

    @Override
    public void start(RuleContext ctx) {
        cleanedVariables.clear();
    }

    @Override
    public Object visit(ASTMethodCall node, RuleContext ctx) {
        if (isCleanMethod(node)) {
            trackCleanMethod(node);
            return super.visit(node, ctx);
        }

        if (isTargetMethod(node)) {
            checkFileInclusionVulnerability(node, ctx);
        }
        return super.visit(node, ctx);
    }

    private boolean isCleanMethod(ASTMethodCall node) {
        String methodName = getFullMethodName(node);
        for (String cleanMethod : CLEAN_METHODS) {
            if (methodName.endsWith(cleanMethod)) {
                return true;
            }
        }
        return false;
    }

    private boolean isTargetMethod(ASTMethodCall node) {
        String methodName = getFullMethodName(node);
        for (String targetMethod : TARGET_METHODS) {
            if (methodName.endsWith(targetMethod)) {
                return true;
            }
        }
        return false;
    }

    private void checkFileInclusionVulnerability(ASTMethodCall node, RuleContext ctx) {
        for (ASTExpression arg : node.getArguments()) {
            if (hasUnresolvedPath(arg)) {
                addViolation(ctx, node, "Potential file inclusion via variable");
                return;
            }
        }
    }

    private boolean hasUnresolvedPath(ASTExpression expr) {
        if (expr instanceof ASTMethodCall) {
            ASTMethodCall call = (ASTMethodCall) expr;
            if (isJoinMethod(call)) {
                for (ASTExpression joinArg : call.getArguments()) {
                    if (containsUnresolvedVariable(joinArg)) {
                        return true;
                    }
                }
            }
            return false;
        }
        return containsUnresolvedVariable(expr);
    }

    private boolean isJoinMethod(ASTMethodCall node) {
        String methodName = getFullMethodName(node);
        for (String joinMethod : PATH_JOIN_METHODS) {
            if (methodName.endsWith(joinMethod)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsUnresolvedVariable(ASTExpression expr) {
        if (expr instanceof ASTVariableAccess) {
            return isUnresolvedVariable((ASTVariableAccess) expr);
        } else if (expr instanceof ASTBinaryExpression) {
            ASTBinaryExpression binExp = (ASTBinaryExpression) expr;
            return containsUnresolvedVariable(binExp.getLeftOperand()) || 
                   containsUnresolvedVariable(binExp.getRightOperand());
        }
        return false;
    }

    private String getFullMethodName(ASTMethodCall node) {
        StringBuilder sb = new StringBuilder();
        if (node.getQualifier() != null) {
            sb.append(node.getQualifier()).append(".");
        }
        sb.append(node.getMethodName());
        return sb.toString();
    }

    private void trackCleanMethod(ASTMethodCall node) {
        if (!node.getArguments().isEmpty()) {
            ASTExpression arg = node.getArguments().get(0);
            if (arg instanceof ASTVariableAccess) {
                ASTVariableAccess varAccess = (ASTVariableAccess) arg;
                cleanedVariables.put(varAccess.getReferencedDeclarator(), node);
            }
        }
    }

    private boolean isUnresolvedVariable(ASTVariableAccess varAccess) {
        return varAccess.getReferencedDeclarator() == null || 
              (!cleanedVariables.containsKey(varAccess.getReferencedDeclarator()) && 
               !isSafeMethodCall(varAccess.getReferencedDeclarator()));
    }

    private boolean isSafeMethodCall(ASTVariableDeclaratorId varDecl) {
        ASTVariableDeclaration varDeclNode = varDecl.getFirstParentOfType(ASTVariableDeclaration.class);
        if (varDeclNode == null) return false;
        
        ASTAssignableExpr initializer = varDeclNode.getInitializer();
        if (initializer instanceof ASTMethodCall) {
            return isCleanMethod((ASTMethodCall) initializer);
        }
        return false;
    }
}