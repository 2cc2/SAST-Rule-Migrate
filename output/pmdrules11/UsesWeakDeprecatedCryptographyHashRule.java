/**
 * PMD Rule to detect usage of weak/deprecated cryptographic hash functions
 */
package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.ASTMethodCall;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;

import java.util.HashMap;
import java.util.Map;

public class UsesWeakDeprecatedCryptographyHashRule extends AbstractJavaRule {
    private static final Map<String, String[]> BLOCKLIST = new HashMap<>();
    
    static {
        BLOCKLIST.put("golang.org.x.crypto.md4", new String[]{"New"});
        BLOCKLIST.put("golang.org.x.crypto.ripemd160", new String[]{"New"});
    }

    public UsesWeakDeprecatedCryptographyHashRule() {
        definePropertyDescriptor(PropertyFactory.intProperty("severity")
                .desc("Severity level")
                .defaultValue(4)  // Medium severity
                .build());
        setMessage("Use of deprecated weak cryptographic primitive");
    }

    @Override
    public Object visit(ASTMethodCall node, Object data) {
        String methodName = node.getMethodName();
        String qualifiedName = node.getQualifiedName();
        
        for (Map.Entry<String, String[]> entry : BLOCKLIST.entrySet()) {
            String pkg = entry.getKey();
            if (qualifiedName.startsWith(pkg)) {
                for (String forbiddenMethod : entry.getValue()) {
                    if (methodName.equals(forbiddenMethod)) {
                        addViolation(data, node);
                        return super.visit(node, data);
                    }
                }
            }
        }
        return super.visit(node, data);
    }
}