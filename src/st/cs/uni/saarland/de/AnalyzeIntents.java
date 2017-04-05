package st.cs.uni.saarland.de;

import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.Stmt;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;

public class AnalyzeIntents implements Runnable {
    private final IntentInfo intentInfo;
    private final SootMethod currentSootMethod;
    private final Unit unitOfStartMethod;
    private final MHGDominatorsFinder<Unit> dominatorFinder;
    private Value registerOfIntent;

    public AnalyzeIntents(SootMethod startMethod, Unit unitOfInvoke, SootMethod methodOfInvoke){
        intentInfo = new IntentInfo(startMethod.getSignature(), methodOfInvoke.getSignature());
        this.unitOfStartMethod = unitOfInvoke;
        this.currentSootMethod = methodOfInvoke;
        this.dominatorFinder = new MHGDominatorsFinder<>(new ExceptionalUnitGraph(currentSootMethod.getActiveBody()));
    }

    public IntentInfo getIntentInfo(){
        return intentInfo;
    }

    @Override
    public void run() {
        if(unitOfStartMethod == null){
            return;
        }
        Unit workingUnit = dominatorFinder.getImmediateDominator(unitOfStartMethod);
        for(Value arg : ((Stmt)unitOfStartMethod).getInvokeExpr().getArgs()){
            if(arg.getType().toString().equals(START_ACTIVITY_CONSTANTS.INTENT_CLASS)){
                registerOfIntent = arg;
                break;
            }
        }
        AnalyseIntentSwitch intentsSwitch = new AnalyseIntentSwitch(registerOfIntent, currentSootMethod, intentInfo);
        while(workingUnit != null && !intentsSwitch.isDone()){
            workingUnit.apply(intentsSwitch);
            workingUnit = dominatorFinder.getImmediateDominator(workingUnit);
        }
    }
}
