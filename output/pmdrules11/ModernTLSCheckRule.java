package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.*;
import java.util.*;

public class ModernTLSCheckRule extends AbstractJavaRule {
    private static final List<String> GOOD_CIPHERS = Arrays.asList(
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
    );
    private static final int MIN_VERSION = 0x0304;
    private static final int MAX_VERSION = 0x0304;

    @Override
    public Object visit(ASTVariableDeclarator node, Object data) {
        if (node.getType() != null && 
            "javax.net.ssl.SSLContext".equals(node.getType().toString())) {
            checkTLSConfig(node, data);
        }
        return super.visit(node, data);
    }

    private void checkTLSConfig(ASTVariableDeclarator node, Object data) {
        // Implementation to check TLS version and ciphers
        addViolation(data, node, "Modern TLS check failed");
    }
}

public class IntermediateTLSCheckRule extends AbstractJavaRule {
    private static final List<String> GOOD_CIPHERS = Arrays.asList(
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
    );
    private static final int MIN_VERSION = 0x0303;
    private static final int MAX_VERSION = 0x0304;

    @Override
    public Object visit(ASTVariableDeclarator node, Object data) {
        if (node.getType() != null && 
            "javax.net.ssl.SSLContext".equals(node.getType().toString())) {
            checkTLSConfig(node, data);
        }
        return super.visit(node, data);
    }

    private void checkTLSConfig(ASTVariableDeclarator node, Object data) {
        addViolation(data, node, "Intermediate TLS check failed");
    }
}