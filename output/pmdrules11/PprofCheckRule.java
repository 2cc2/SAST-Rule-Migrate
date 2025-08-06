package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.ASTImportDeclaration;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;
import net.sourceforge.pmd.RuleContext;

public class PprofCheckRule extends AbstractJavaRule {
    
    private static final String IMPORT_PATH = "net/http/pprof";
    private static final String IMPORT_NAME = "_";
    private static final PropertyDescriptor<String> IMPORT_PATH_PROPERTY = 
        PropertyFactory.stringProperty("importPath")
                      .desc("Path of the pprof import to detect")
                      .defaultValue(IMPORT_PATH)
                      .build();

    public PprofCheckRule() {
        definePropertyDescriptor(IMPORT_PATH_PROPERTY);
    }

    @Override
    public Object visit(ASTImportDeclaration node, Object data) {
        String importName = node.getImportedName();
        String alias = node.getAlias() == null ? "" : node.getAlias();

        if (getProperty(IMPORT_PATH_PROPERTY).equals(importName) && IMPORT_NAME.equals(alias)) {
            RuleContext ctx = (RuleContext) data;
            ctx.addViolation(node, "Profiling endpoint is automatically exposed on /debug/pprof");
        }
        return super.visit(node, data);
    }
}