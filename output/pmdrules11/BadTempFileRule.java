package com.example.pmdrules;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.java.ast.ASTAssignStmt;
import net.sourceforge.pmd.lang.java.ast.ASTCallExpression;
import net.sourceforge.pmd.lang.java.ast.ASTExpression;
import net.sourceforge.pmd.lang.java.ast.ASTVariableId;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class BadTempFileRule extends AbstractJavaRule {
    private static final Set<String> READER_METHODS = new HashSet<>();
    private static final Set<String> COPY_METHODS = new HashSet<>();
    
    static {
        READER_METHODS.add("compress.gzip.NewReader");
        READER_METHODS.add("compress.zlib.NewReader");
        READER_METHODS.add("compress.zlib.NewReaderDict");
        READER_METHODS.add("compress.bzip2.NewReader");
        READER_METHODS.add("compress.flate.NewReader");
        READER_METHODS.add("compress.flate.NewReaderDict");
        READER_METHODS.add("compress.lzw.NewReader");
        READER_METHODS.add("archive.tar.NewReader");
        READER_METHODS.add("archive.zip.NewReader");
        READER_METHODS.add("archive.zip.File.Open");
        
        COPY_METHODS.add("io.Copy");
        COPY_METHODS.add("io.CopyBuffer");
    }

    private Map<Object, Object> readerVarObj = new HashMap<>();

    @Override
    public Object visit(ASTAssignStmt node, Object data) {
        RuleContext ctx = (RuleContext) data;
        for (ASTExpression expr : node.findChildrenOfType(ASTExpression.class)) {
            if (expr instanceof ASTCallExpression) {
                ASTCallExpression callExpr = (ASTCallExpression) expr;
                if (isReaderCall(callExpr)) {
                    ASTVariableId id = node.getFirstDescendantOfType(ASTVariableId.class);
                    if (id != null && !"_".equals(id.getName())) {
                        readerVarObj.put(id.getBinding(), null);
                    }
                }
            }
        }
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTCallExpression node, Object data) {
        RuleContext ctx = (RuleContext) data;
        if (isCopyCall(node)) {
            ASTExpression arg = node.getArgument(1);
            if (arg instanceof ASTVariableId) {
                ASTVariableId id = (ASTVariableId) arg;
                if (readerVarObj.containsKey(id.getBinding())) {
                    addViolation(ctx, node, "Potential DoS vulnerability via decompression bomb");
                }
            }
        }
        return super.visit(node, data);
    }

    private boolean isReaderCall(ASTCallExpression node) {
        String methodCall = getFullyQualifiedMethodName(node);
        return READER_METHODS.contains(methodCall);
    }

    private boolean isCopyCall(ASTCallExpression node) {
        String methodCall = getFullyQualifiedMethodName(node);
        return COPY_METHODS.contains(methodCall);
    }

    private String getFullyQualifiedMethodName(ASTCallExpression node) {
        return node.getMethodName();
    }
}