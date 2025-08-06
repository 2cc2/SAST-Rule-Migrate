package net.sourceforge.pmd.lang.java.rule.security;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.ast.Node;

public class SqlStringConcatenationRule extends AbstractJavaRule {

    @Override
    public Object visit(ASTMethodDeclaration node, Object data) {
        checkForSqlConcatenation(node, data);
        return super.visit(node, data);
    }

    private void checkForSqlConcatenation(ASTMethodDeclaration methodNode, Object data) {
        // Check for string concatenation patterns
        for (ASTVariableDeclaratorId var : methodNode.findDescendantsOfType(ASTVariableDeclaratorId.class)) {
            ASTVariableDeclarator declarator = (ASTVariableDeclarator) var.getParent();
            Node initializerNode = declarator.jjtGetChild(1);
            
            if (initializerNode != null && initializerNode instanceof ASTVariableInitializer) {
                ASTVariableInitializer initializer = (ASTVariableInitializer) initializerNode;
                Node exprNode = initializer.jjtGetChild(0);
                if (exprNode != null && exprNode instanceof ASTAdditiveExpression) {
                    ASTAdditiveExpression addExpr = (ASTAdditiveExpression) exprNode;
                    if (containsVariableReference(addExpr, var.getName())) {
                        // Check if the concatenated string is used in prepareStatement
                        String varName = var.getName();
                        for (ASTPrimaryExpression mcall : methodNode.findDescendantsOfType(ASTPrimaryExpression.class)) {
                            ASTName methodName = mcall.getFirstChildOfType(ASTName.class);
                            if (methodName != null && "prepareStatement".equals(methodName.getImage())) {
                                // Verify the argument to prepareStatement references our variable
                                ASTArgumentList args = mcall.getFirstChildOfType(ASTArgumentList.class);
                                if (args != null) {
                                    for (int i = 0; i < args.getNumChildren(); i++) {
                                        Node arg = args.getChild(i);
                                        if (arg instanceof ASTName) {
                                            ASTName name = (ASTName) arg;
                                            if (name.getImage().contains(varName)) {
                                                // Found SQL injection vulnerability
                                                addViolation(data, declarator, "In " + methodNode.getName() + 
                                                    ", " + varName + " is used to construct a SQL query via string concatenation.");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private boolean containsVariableReference(ASTAdditiveExpression expr, String varName) {
        for (ASTName name : expr.findDescendantsOfType(ASTName.class)) {
            if (varName.equals(name.getImage())) {
                return true;
            }
        }
        return false;
    }
}