package com.example.pmdrules;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.java.ast.ASTImportDeclaration;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import java.util.HashMap;
import java.util.Map;

public class BlocklistedImportsRule extends AbstractJavaRule {
    private static final Map<String, String> BLOCKLISTED_IMPORTS = new HashMap<>();

    static {
        BLOCKLISTED_IMPORTS.put("crypto.md5", "Blocklisted import crypto.md5: weak cryptographic primitive");
        BLOCKLISTED_IMPORTS.put("crypto.des", "Blocklisted import crypto.des: weak cryptographic primitive");
        BLOCKLISTED_IMPORTS.put("crypto.rc4", "Blocklisted import crypto.rc4: weak cryptographic primitive");
        BLOCKLISTED_IMPORTS.put("net.http.cgi", "Blocklisted import net.http.cgi: vulnerable to Httpoxy attack (CVE-2016-5386)");
        BLOCKLISTED_IMPORTS.put("crypto.sha1", "Blocklisted import crypto.sha1: weak cryptographic primitive");
        BLOCKLISTED_IMPORTS.put("golang.org.x.crypto.md4", "Blocklisted import golang.org.x.crypto.md4: deprecated and weak cryptographic primitive");
        BLOCKLISTED_IMPORTS.put("golang.org.x.crypto.ripemd160", "Blocklisted import golang.org.x.crypto.ripemd160: deprecated and weak cryptographic primitive");
    }

    @Override
    public Object visit(ASTImportDeclaration node, Object data) {
        String importName = node.getImportedName();
        if (BLOCKLISTED_IMPORTS.containsKey(importName)) {
            RuleContext rc = (RuleContext) data;
            rc.getReport().addRuleViolation(
                createRuleViolation(rc, node, BLOCKLISTED_IMPORTS.get(importName))
            );
        }
        return super.visit(node, data);
    }
}