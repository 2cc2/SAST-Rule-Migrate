package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class DecompressionBombCheckRule extends AbstractJavaRule {
    private static final Set<String> READER_METHODS = new HashSet<>();
    private static final Set<String> COPY_METHODS = new HashSet<>();
    
    static {
        READER_METHODS.add("NewReader"); 
        READER_METHODS.add("NewReaderDict");
        READER_METHODS.add("Open");
        COPY_METHODS.add("Copy");
        COPY_METHODS.add("CopyBuffer");
    }

    private final Map<String, Boolean> trackedReaders = new HashMap<>();

    @Override
    public Object visit(ASTVariableDeclarator node, Object data) {
        ASTExpression init = node.getInitializer();
        if (init instanceof ASTMethodCall) {
            ASTMethodCall call = (ASTMethodCall) init;
            if (READER_METHODS.contains(call.getMethodName())) {
                ASTVariableDeclaratorId varId = node.getVarId();
                if (varId != null && !"_".equals(varId.getName())) {
                    trackedReaders.put(varId.getName(), true);
                }
            }
        }
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTMethodCall node, Object data) {
        if (COPY_METHODS.contains(node.getMethodName()) 
            && node.getArguments().size() > 1) {
            ASTExpression arg = node.getArgument(1);
            if (arg instanceof ASTVariableDeclaratorId
                && trackedReaders.containsKey(((ASTVariableDeclaratorId)arg).getName())) {
                addViolation(data, node);
            }
        }
        return super.visit(node, data);
    }
}