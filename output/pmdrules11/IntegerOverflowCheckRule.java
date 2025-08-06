package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.ASTAssignExpr;
import net.sourceforge.pmd.lang.java.ast.ASTCastExpr;
import net.sourceforge.pmd.lang.java.ast.ASTExpression;
import net.sourceforge.pmd.lang.java.ast.ASTName;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryExpression;
import net.sourceforge.pmd.lang.java.ast.ASTPrimaryPrefix;
import net.sourceforge.pmd.lang.java.ast.JavaNode;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.ast.Node;

import java.util.HashMap;
import java.util.Map;

public class IntegerOverflowCheckRule extends AbstractJavaRule {
    
    private final Map<String, Node> atoiVarMap = new HashMap<>();

    public IntegerOverflowCheckRule() {
        addRuleChainVisit(ASTAssignExpr.class);
        addRuleChainVisit(ASTCastExpr.class);
    }

    @Override
    public Object visit(ASTAssignExpr node, Object data) {
        if (node.getRightHandSide() instanceof ASTPrimaryExpression) {
            ASTPrimaryExpression rhs = (ASTPrimaryExpression) node.getRightHandSide();
            if (isStrconvAtoiCall(rhs)) {
                Node lhs = node.getLeftHandSide();
                if (lhs instanceof ASTName) {
                    ASTName varName = (ASTName) lhs;
                    atoiVarMap.put(varName.getImage(), node);
                }
            }
        }
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTCastExpr node, Object data) {
        String targetType = node.getTypeNode().getTypeImage();
        if ("int".equals(targetType) || "short".equals(targetType)) {
            ASTExpression castExpr = node.getExpr();
            if (castExpr instanceof ASTName) {
                ASTName varName = (ASTName) castExpr;
                if (atoiVarMap.containsKey(varName.getImage())) {
                    addViolation(data, node, "Potential integer overflow from strconv.Atoi result conversion");
                }
            }
        }
        return super.visit(node, data);
    }

    private boolean isStrconvAtoiCall(ASTPrimaryExpression expr) {
        if (expr.jjtGetNumChildren() > 0) {
            Node firstChild = expr.jjtGetChild(0);
            if (firstChild instanceof ASTPrimaryPrefix) {
                String image = firstChild.getImage();
                return image != null && image.contains("Integer.parseInt");
            }
        }
        return false;
    }
}