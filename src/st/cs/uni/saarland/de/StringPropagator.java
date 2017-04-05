package st.cs.uni.saarland.de;

import java.util.HashSet;

import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.StringConstant;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;

public class StringPropagator implements Runnable {
	protected final SootMethod currentSootMethod;
    protected final Unit unitOfStartMethod;
    protected final MHGDominatorsFinder<Unit> dominatorsFinder;
    protected final Value registerToTrack;
    private String result = null;

    public String getResult(){
        return result;
    }

    public StringPropagator(SootMethod currentSootMethod, Unit unitOfStartMethod, Value registerToTrack){
        this.currentSootMethod = currentSootMethod;
        this.unitOfStartMethod = unitOfStartMethod;
        this.registerToTrack = registerToTrack;
        this.dominatorsFinder = new MHGDominatorsFinder<>(new ExceptionalUnitGraph(currentSootMethod.getActiveBody()));
    }

    @Override
    public void run() {
        if(registerToTrack instanceof StringConstant){
            result = ((StringConstant)registerToTrack).value;
            return;
        }
        if(unitOfStartMethod == null){
            return;
        }
        Unit workingUnit = dominatorsFinder.getImmediateDominator(unitOfStartMethod);
        StringPropagatorSwitch stringPropagatorSwitch = new StringPropagatorSwitch(registerToTrack, currentSootMethod, new HashSet<>());
        while (workingUnit != null && !stringPropagatorSwitch.isDone()){
            workingUnit.apply(stringPropagatorSwitch);
            workingUnit = dominatorsFinder.getImmediateDominator(workingUnit);
        }
        result = stringPropagatorSwitch.getResult();
    }
}
