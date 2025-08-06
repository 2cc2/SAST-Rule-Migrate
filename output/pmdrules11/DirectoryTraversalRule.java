package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.*;
import net.sourceforge.pmd.properties.*;
import java.util.regex.Pattern;

public class DirectoryTraversalRule extends AbstractJavaRule {
    private static final String DEFAULT_PATTERN = "http\\.Dir\\(\"\\/\"\\)|http\\.Dir\\('\\/'\\)";
    private static final PropertyDescriptor<Pattern> PATTERN = 
        PropertyFactory.regexProperty("pattern")
            .desc("Pattern to detect directory traversal vulnerabilities")
            .defaultValue(Pattern.compile(DEFAULT_PATTERN))
            .build();

    public DirectoryTraversalRule() {
        definePropertyDescriptor(PATTERN);
    }

    @Override
    public Object visit(ASTMethodCall node, Object data) {
        Pattern pattern = getProperty(PATTERN);
        
        for (ASTExpression arg : node.getArguments()) {
            if (arg instanceof ASTStringLiteral) {
                ASTStringLiteral literal = (ASTStringLiteral) arg;
                String methodCall = node.getMethodName() + "(\"" + literal.getLiteral() + "\")";
                if (pattern.matcher(methodCall).matches()) {
                    addViolation(data, node);
                }
            }
        }
        return super.visit(node, data);
    }
}