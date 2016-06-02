package st.cs.uni.saarland.de;

import java.util.HashSet;
import java.util.Set;

import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeStmt;
import soot.jimple.StaticInvokeExpr;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;

public class BundlesPropagatorSwitch extends AbstractStmtSwitch {
    private final Value register;
    private final SootMethod sootMethod;
    private boolean isDone = false;
    private Set<String> results;

    public Set<String> getResults(){
        return results;
    }

    public boolean isDone(){
        return isDone;
    }

    public BundlesPropagatorSwitch(SootMethod currentSootMethod, Value register){
        this.register = register;
        this.sootMethod = currentSootMethod;
    }

    public void caseInvokeStmt(InvokeStmt stmt){
        if(stmt.getInvokeExpr() instanceof StaticInvokeExpr){
            isDone = true;
            return;
        }
        if(stmt.getInvokeExpr().getMethod().getSignature().equals(START_ACTIVITY_CONSTANTS.BUNDLE_INIT)){

            return;
        }
        Value registerToCopmare = stmt.getInvokeExpr().getUseBoxes().get(stmt.getInvokeExpr().getUseBoxes().size() - 1).getValue();
        if(registerToCopmare.equals(register) && stmt.getInvokeExpr().getMethod().getSignature().equals(START_ACTIVITY_CONSTANTS.PUT_STRING_TO_BUNDLE)){
            MHGDominatorsFinder<Unit> dominatorsFinder = new MHGDominatorsFinder<>(new ExceptionalUnitGraph(sootMethod.getActiveBody()));
            StringPropagatorSwitch stringPropagatorSwitch = new StringPropagatorSwitch(stmt.getInvokeExpr().getArg(0), sootMethod, new HashSet<>());
            Unit currentUnit = dominatorsFinder.getImmediateDominator(stmt);
            while (currentUnit != null && !stringPropagatorSwitch.isDone()){
                currentUnit.apply(stringPropagatorSwitch);
                currentUnit = dominatorsFinder.getImmediateDominator(currentUnit);
            }
            if(stringPropagatorSwitch.getResult() != null){
                results.add(stringPropagatorSwitch.getResult());
            }
        }
    }
}
