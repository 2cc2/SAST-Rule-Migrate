package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;
import java.util.regex.Pattern;
import java.util.List;
import java.util.Arrays;

public class HardcodedCredentialsRule extends AbstractJavaRule {
    
    private static final List<SecretPattern> SECRET_PATTERNS = Arrays.asList(
        new SecretPattern("RSA private key", Pattern.compile("-----BEGIN RSA PRIVATE KEY-----")),
        new SecretPattern("SSH (DSA) private key", Pattern.compile("-----BEGIN DSA PRIVATE KEY-----")),
        new SecretPattern("SSH (EC) private key", Pattern.compile("-----BEGIN EC PRIVATE KEY-----")),
        new SecretPattern("PGP private key block", Pattern.compile("-----BEGIN PGP PRIVATE KEY BLOCK-----")),
        new SecretPattern("Twitter OAuth", Pattern.compile("[tT][wW][iI][tT][tT][eE][rR].*[''|\"][0-9a-zA-Z]{35,44}[''|\"]"))
    );

    private static final PropertyDescriptor<Pattern> PATTERN = PropertyFactory.regexProperty("pattern")
            .desc("Pattern to match credential-like variable names")
            .defaultValue(Pattern.compile("(?i)passwd|pass|password|pwd|secret|token|pw|apiKey|bearer|cred"))
            .build();

    private static final PropertyDescriptor<Double> ENTROPY_THRESHOLD = PropertyFactory.doubleProperty("entropyThreshold")
            .desc("Entropy threshold for string detection")
            .defaultValue(80.0)
            .build();

    public HardcodedCredentialsRule() {
        definePropertyDescriptor(PATTERN);
        definePropertyDescriptor(ENTROPY_THRESHOLD);
    }

    @Override
    public Object visit(ASTVariableDeclaratorId node, Object data) {
        Pattern pattern = getProperty(PATTERN);
        if (pattern.matcher(node.getName()).matches()) {
            ASTVariableInitializer initializer = node.getInitializer();
            if (initializer != null) {
                ASTExpression initExpr = initializer.getInitialExpression();
                if (initExpr instanceof ASTLiteral) {
                    checkForSecret((ASTLiteral)initExpr, data);
                }
            }
        }
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTAssignmentOperator node, Object data) {
        ASTExpression left = node.getLeftOperand();
        if (left instanceof ASTName) {
            Pattern pattern = getProperty(PATTERN);
            if (pattern.matcher(((ASTName)left).getImage()).matches()) {
                ASTExpression right = node.getRightOperand();
                if (right instanceof ASTLiteral) {
                    checkForSecret((ASTLiteral)right, data); 
                }
            }
        }
        return super.visit(node, data);
    }

    private void checkForSecret(ASTLiteral literal, Object data) {
        if (literal.isStringLiteral()) {
            String value = literal.getImage();
            if (isSecretPattern(value) || isHighEntropyString(value)) {
                addViolation(data, literal);
            }
        }
    }

    private boolean isHighEntropyString(String str) {
        // Implement proper entropy calculation
        return str.length() > 20 && 
               str.matches(".*[a-zA-Z].*") && 
               str.matches(".*[0-9].*");
    }

    private boolean isSecretPattern(String str) {
        return SECRET_PATTERNS.stream()
               .anyMatch(p -> p.pattern.matcher(str).matches());
    }

    private static final class SecretPattern {
        final String name;
        final Pattern pattern;

        SecretPattern(String name, Pattern pattern) {
            this.name = name;
            this.pattern = pattern;
        }
    }
}