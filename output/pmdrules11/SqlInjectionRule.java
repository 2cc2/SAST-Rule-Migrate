package com.example.pmdrules;

import net.sourceforge.pmd.lang.java.ast.*;
import net.sourceforge.pmd.lang.java.rule.AbstractJavaRule;
import java.util.regex.Pattern;

public class SqlInjectionRule extends AbstractJavaRule {
    private static final Pattern SQL_PATTERN = 
        Pattern.compile("(?i)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE)( |\\n|\\r|\\t)");
    private static final Pattern FORMAT_PATTERN = 
        Pattern.compile("%[^bdoxXfFp]");

    @Override
    public Object visit(ASTMethodCall methodCall, Object data) {
        if (methodCall != null) {
            checkSqlConcatenation(methodCall, data);
            checkSqlFormatting(methodCall, data);
        }
        return super.visit(methodCall, data);
    }

    private void checkSqlConcatenation(ASTMethodCall methodCall, Object data) {
        String methodName = methodCall.getMethodName();
        String className = getClassName(methodCall);
        
        if (isSqlMethod(className, methodName)) {
            ASTExpression arg = getSqlArgument(methodCall);
            if (arg != null && isStringConcatenation(arg)) {
                String image = arg.getImage();
                if (image != null && containsSqlPattern(image)) {
                    addViolation(data, methodCall, "SQL string concatenation vulnerability detected");
                }
            }
        }
    }

    private boolean isSqlMethod(String className, String methodName) {
        if (className == null || methodName == null) {
            return false;
        }
        return ("java.sql.Statement".equals(className) || 
                "java.sql.PreparedStatement".equals(className)) &&
               ("execute".equals(methodName) ||
                "executeQuery".equals(methodName) ||
                "executeUpdate".equals(methodName));
    }

    private ASTExpression getSqlArgument(ASTMethodCall methodCall) {
        return methodCall.getArguments().isEmpty() ? null : methodCall.getArguments().get(0);
    }

    private boolean isStringConcatenation(ASTExpression expr) {
        return expr instanceof ASTAdditiveExpression && 
               ((ASTAdditiveExpression)expr).getOperator() == ASTAdditiveExpression.Operator.PLUS;
    }

    private boolean containsSqlPattern(String str) {
        return str != null && SQL_PATTERN.matcher(str).find();
    }

    private String getClassName(ASTMethodCall methodCall) {
        return methodCall.getQualifier() instanceof ASTClassOrInterfaceType ? 
               ((ASTClassOrInterfaceType)methodCall.getQualifier()).getImage() : null;
    }
}