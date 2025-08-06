package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;

public class WeakKeyStrengthRule extends AbstractJavaRule {
    private static final String RSA_GENERATE_KEY = "GenerateKey";
    private static final String CRYPTO_RSA = "crypto.rsa";
    private static final int MIN_KEY_BITS = 2048;
    
    public WeakKeyStrengthRule() {
        setMessage("RSA keys should be at least " + MIN_KEY_BITS + " bits");
    }
    
    @Override
    public Object visit(ASTMethodCall node, Object data) {
        if (isGenerateKeyCall(node)) {
            ASTArguments args = node.getFirstChildOfType(ASTArguments.class);
            if (args != null && args.size() >= 2) {
                ASTExpression secondArg = args.get(1);
                if (secondArg != null) {
                    Object constValue = secondArg.getConstantValue();
                    if (constValue instanceof Number) {
                        int bits = ((Number) constValue).intValue();
                        if (bits < MIN_KEY_BITS) {
                            asCtx(data).addViolation(node);
                        }
                    }
                }
            }
        }
        return super.visit(node, data);
    }
    
    private boolean isGenerateKeyCall(ASTMethodCall node) {
        ASTClassOrInterfaceType type = node.getFirstChildOfType(ASTClassOrInterfaceType.class);
        return node.getMethodName().equals(RSA_GENERATE_KEY) &&
               type != null && 
               type.getImage().equals(CRYPTO_RSA);
    }
}