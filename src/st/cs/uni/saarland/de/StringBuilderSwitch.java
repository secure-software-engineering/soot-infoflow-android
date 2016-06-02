package st.cs.uni.saarland.de;

import soot.SootMethod;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.NewExpr;
import soot.jimple.StaticInvokeExpr;

public class StringBuilderSwitch extends AbstractStmtSwitch {
	private Value registerOfStringBuilder;
    private boolean isDone = false;
    private String result;
    private final SootMethod currentSootMethod;

    public String getResult(){
        return result;
    }

    private void addToResults(String toAdd){
        if(result == null || result.isEmpty()){
            result = toAdd;
        }
        else{
            result = (toAdd + result);
        }
    }

    public boolean isDone(){return isDone;}

    public StringBuilderSwitch(Value regOfStringBuilder, SootMethod currentSootMethod){
        this.registerOfStringBuilder = regOfStringBuilder;
        this.currentSootMethod = currentSootMethod;
    }


    public void caseAssignStmt(AssignStmt stmt){
        if(!stmt.containsInvokeExpr()){
            if(stmt.getLeftOp().equals(registerOfStringBuilder) && stmt.getRightOp() instanceof NewExpr){
                NewExpr newExpr = (NewExpr)stmt.getRightOp();
                if(newExpr.getType().toString().equals(STRING_BUILDER_CONSTANTS.CLASS_NAME)){
                    isDone = true;
                    return;
                }
            }
        }
        else{
            InvokeExpr invokeExpr = stmt.getInvokeExpr();
            if(invokeExpr instanceof StaticInvokeExpr){
                //static invoke expt doesn't have use boxes
                return;
            }
            Value registerToCopmare = invokeExpr.getUseBoxes().get(stmt.getInvokeExpr().getUseBoxes().size() - 1).getValue();
            if(registerToCopmare.equals(registerOfStringBuilder) && invokeExpr.getMethod().getSignature().equals(STRING_BUILDER_CONSTANTS.APPEND)){
                Value arg = invokeExpr.getArg(0);
                StringPropagator stringPropagator = new StringPropagator(currentSootMethod, stmt, arg);
                stringPropagator.run();
                String res = stringPropagator.getResult();
                if(res != null){
                    addToResults(res);
                }
            }
        }
    }

}
