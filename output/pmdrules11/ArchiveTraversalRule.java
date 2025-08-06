package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.lang.java.types.TypeTestUtil;
import java.util.Arrays;
import java.util.List;

public class ArchiveTraversalRule extends AbstractJavaRule {
    private static final List<String> TARGET_ARG_TYPES = Arrays.asList(
        "archive/zip.File",
        "archive/tar.Header"
    );
    
    private static final List<String[]> TARGET_METHODS = Arrays.asList(
        new String[]{"java.io.File", "getPath"},
        new String[]{"java.nio.file.Path", "toString"}
    );

    @Override
    public Object visit(ASTMethodCall node, Object data) {
        if (isTargetMethodCall(node)) {
            for (ASTExpression arg : node.getArguments()) {
                if (isUnsafeArchiveType(arg)) {
                    addViolation(data, node);
                    break;
                }
            }
        }
        return super.visit(node, data);
    }

    private boolean isTargetMethodCall(ASTMethodCall node) {
        return TARGET_METHODS.stream().anyMatch(method -> 
            TypeTestUtil.isA(method[0], node.getQualifier()) &&
            node.getMethodName().equals(method[1])
        );
    }

    private boolean isUnsafeArchiveType(ASTExpression expr) {
        return TARGET_ARG_TYPES.stream().anyMatch(type -> 
            TypeTestUtil.isA(type, expr)
        );
    }
}