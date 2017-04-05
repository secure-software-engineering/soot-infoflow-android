package st.cs.uni.saarland.de;

import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;

public class StringBuilderPropagator implements Runnable {
	protected final SootMethod currentSootMethod;
    protected final Unit unitOfStartMethod;
    protected final MHGDominatorsFinder<Unit> dominatorsFinder;
    protected final Value registerOfStringBuilderToTrack;
    private String result = null;

    public String getResult(){
        return result;
    }

    public StringBuilderPropagator(SootMethod currentSootMethod, Unit unitOfStartMethod, Value registerOfStringBuilderToTrack){
        this.currentSootMethod = currentSootMethod;
        this.unitOfStartMethod = unitOfStartMethod;
        this.registerOfStringBuilderToTrack = registerOfStringBuilderToTrack;
        this.dominatorsFinder = new MHGDominatorsFinder<>(new ExceptionalUnitGraph(currentSootMethod.getActiveBody()));
    }

    @Override
    public void run() {
        if(unitOfStartMethod == null){
            return;
        }
        Unit workingUnit = dominatorsFinder.getImmediateDominator(unitOfStartMethod);
        StringBuilderSwitch stringBuilderPropagatorSwitch = new StringBuilderSwitch(registerOfStringBuilderToTrack, currentSootMethod);
        while (workingUnit != null && !stringBuilderPropagatorSwitch.isDone()){
            workingUnit.apply(stringBuilderPropagatorSwitch);
            workingUnit = dominatorsFinder.getImmediateDominator(workingUnit);
        }
        result = stringBuilderPropagatorSwitch.getResult();
    }
}
