package st.cs.uni.saarland.de;

import soot.SootMethod;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.ClassConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;

public class AnalyzeComponentSwitch extends AbstractStmtSwitch {
    private final Value registerOfComponent;
    private final SootMethod currentMethod;
    private String result;

    public String getResult(){
        return result;
    }

    public AnalyzeComponentSwitch(Value reg, SootMethod currentSootMethod){
        registerOfComponent = reg;
        currentMethod = currentSootMethod;
    }

    public void caseInvokeStmt(InvokeStmt stmt) {
        InvokeExpr expr = stmt.getInvokeExpr();
        if(expr.getUseBoxes().get(expr.getUseBoxes().size() - 1).getValue().equals(registerOfComponent)) {
            if (expr.getMethod().getSignature().equals(START_ACTIVITY_CONSTANTS.COMPONENT_INIT)) {
                result = processClass(stmt, expr, 1);
            } else if (expr.getMethod().getSignature().equals(START_ACTIVITY_CONSTANTS.COMPONENT_INIT_CLASS)) {
                if (expr.getArg(1) instanceof ClassConstant) {
                    result = ((ClassConstant) expr.getArg(1)).getValue();
                }
            }
        }
    }

    private String processClass(Stmt stmt, InvokeExpr invokeExpr, int paramNumber) {
        StringPropagator stringPropagator = new StringPropagator(currentMethod, stmt, invokeExpr.getArg(paramNumber));
        stringPropagator.run();
        String className = stringPropagator.getResult();
        if(className != null){
            return className;
        }
        return null;
    }
}
