package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import java.util.HashMap;
import java.util.Map;

/**
 * Rule to detect usage of cryptographically weak random number generators
 */
public class WeakRandomNumberGeneratorRule extends AbstractJavaRule {

    private static final Map<String, String[]> WEAK_RANDOM_METHODS = new HashMap<>();
    
    static {
        WEAK_RANDOM_METHODS.put("math/rand", new String[]{
            "New", "Read", "Float32", "Float64", "Int", "Int31", "Int31n",
            "Int63", "Int63n", "Intn", "NormFloat64", "Uint32", "Uint64"
        });
        WEAK_RANDOM_METHODS.put("math/rand/v2", new String[]{
            "New", "Float32", "Float64", "Int", "Int32", "Int32N",
            "Int64", "Int64N", "IntN", "N", "NormFloat64", "Uint32", "Uint32N",
            "Uint64", "Uint64N", "UintN"
        });
    }

    @Override
    public Object visit(ASTCompilationUnit node, Object data) {
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTPrimaryPrefix node, Object data) {
        if (node.jjtGetNumChildren() > 0 && node.jjtGetChild(0) instanceof ASTName) {
            ASTName name = (ASTName) node.jjtGetChild(0);
            String qualifiedName = name.getImage();
            
            for (Map.Entry<String, String[]> entry : WEAK_RANDOM_METHODS.entrySet()) {
                String pkg = entry.getKey();
                if (qualifiedName.startsWith(pkg + ".")) {
                    String methodName = qualifiedName.substring(pkg.length() + 1);
                    for (String weakMethod : entry.getValue()) {
                        if (methodName.equals(weakMethod)) {
                            addViolation(data, node, 
                                "Use of cryptographically weak random number generator (" + 
                                pkg + "). Use crypto/rand instead.");
                            break;
                        }
                    }
                }
            }
        }
        return super.visit(node, data);
    }
}