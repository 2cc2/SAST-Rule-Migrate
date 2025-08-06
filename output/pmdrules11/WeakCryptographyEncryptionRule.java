package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.ASTNameExpr;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import java.util.HashMap;
import java.util.Map;

public class WeakCryptographyEncryptionRule extends AbstractJavaRule {
    private static final Map<String, String[]> BLOCKLIST = new HashMap<>();

    static {
        BLOCKLIST.put("crypto.des", new String[]{"NewCipher", "NewTripleDESCipher"});
        BLOCKLIST.put("crypto.rc4", new String[]{"NewCipher"});
    }

    public WeakCryptographyEncryptionRule() {
        setMessage("Use of weak cryptographic primitive");
    }

    @Override
    public Object visit(ASTNameExpr node, Object data) {
        String image = node.getImage();
        for (Map.Entry<String, String[]> entry : BLOCKLIST.entrySet()) {
            String pkg = entry.getKey();
            for (String func : entry.getValue()) {
                if (image.startsWith(pkg + ".") && image.endsWith("." + func)) {
                    addViolation(data, node);
                    break;
                }
            }
        }
        return super.visit(node, data);
    }
}