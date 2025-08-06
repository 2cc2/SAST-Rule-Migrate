package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;

public class BobRule extends AbstractJavaRule {
    public BobRule() {
        System.out.println("Custom rule loaded.");
    }
}
