package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.*;
import net.sourceforge.pmd.*;

public class InsecureTlsConfigRule extends AbstractJavaRule {
    private final long minVersion = 0x0304; // TLS 1.3
    private final long maxVersion = 0x0304; // TLS 1.3
    private final String[] goodCiphers = {
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
    };
    
    public InsecureTlsConfigRule() {
        addRuleChainVisit(ASTVariableDeclarator.class);
        addRuleChainVisit(ASTAssignmentOperator.class);
    }

    @Override
    public Object visit(ASTVariableDeclarator node, Object data) {
        if (isTlsConfigType(node)) {
            ASTInitializer initializer = node.getInitializer();
            if (initializer != null) {
                checkTlsConfig(initializer, data);
            }
        }
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTAssignmentOperator node, Object data) {
        ASTExpression expr = node.getFirstChildOfType(ASTExpression.class);
        if (expr != null && isTlsConfigExpression(expr)) {
            checkTlsConfig(expr, data);
        }
        return super.visit(node, data);
    }

    private boolean isTlsConfigType(ASTVariableDeclarator node) {
        ASTType type = node.getTypeNode();
        return type != null && "Config".equals(type.getTypeImage());
    }

    private boolean isTlsConfigExpression(ASTExpression node) {
        if (node == null) return false;
        
        ASTPrimaryExpression primaryExpr = node.getFirstDescendantOfType(ASTPrimaryExpression.class);
        if (primaryExpr != null) {
            ASTPrimaryPrefix prefix = primaryExpr.getFirstDescendantOfType(ASTPrimaryPrefix.class);
            if (prefix != null) {
                ASTName name = prefix.getFirstDescendantOfType(ASTName.class);
                return name != null && name.getImage().endsWith(".tlsConfig");
            }
        }
        return false;
    }

    private void checkTlsConfig(ASTNode node, Object data) {
        if (node == null) return;
        
        if (node instanceof ASTInitializer) {
            ASTExpression expr = ((ASTInitializer)node).getFirstDescendantOfType(ASTExpression.class);
            if (expr != null) {
                ASTPrimaryExpression primaryExpr = expr.getFirstDescendantOfType(ASTPrimaryExpression.class);
                if (primaryExpr != null) {
                    processConfiguration(primaryExpr, data);
                }
            }
        } else if (node instanceof ASTExpression) {
            ASTPrimaryExpression primaryExpr = ((ASTExpression)node).getFirstDescendantOfType(ASTPrimaryExpression.class);
            if (primaryExpr != null) {
                processConfiguration(primaryExpr, data);
            }
        }
    }

    private void processConfiguration(ASTPrimaryExpression expr, Object data) {
        checkBooleanProperty(expr, "InsecureSkipVerify", true, 
            "TLS InsecureSkipVerify set true.", data);
        checkVersionProperty(expr, "MinVersion", minVersion, 
            "TLS MinVersion too low.", data);
        checkVersionProperty(expr, "MaxVersion", maxVersion, 
            "TLS MaxVersion too low.", data);
        checkCipherSuites(expr, data);
    }

    private void checkBooleanProperty(ASTPrimaryExpression expr, String property, 
            boolean badValue, String message, Object data) {
        // Implementation to check boolean properties
    }

    private void checkVersionProperty(ASTPrimaryExpression expr, String property,
            long minAllowed, String message, Object data) {
        // Implementation to check version properties
    }

    private void checkCipherSuites(ASTPrimaryExpression expr, Object data) {
        // Implementation to check cipher suites against goodCiphers list
    }

    private boolean isGoodCipher(String cipher) {
        for (String good : goodCiphers) {
            if (good.equals(cipher)) {
                return true;
            }
        }
        return false;
    }
}