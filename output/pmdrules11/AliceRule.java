package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;

public class AliceRule extends AbstractJavaRule {
    public AliceRule() {
        System.out.println("Custom rule loaded.");
    }
}
