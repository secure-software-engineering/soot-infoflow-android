package st.cs.uni.saarland.de;

import java.util.HashSet;
import java.util.Set;

import soot.SootMethod;
import soot.Unit;
import soot.Value;

public class BundlesPropagator extends StringPropagator {
    private final Set<String> results;

    public Set<String> getResults(){
        return results;
    }

    public BundlesPropagator(SootMethod currentSootMethod, Unit unitOfStartMethod, Value registerToTrack) {
        super(currentSootMethod, unitOfStartMethod, registerToTrack);
        results = new HashSet<>();
    }

    @Override
    public void run(){
        if(unitOfStartMethod == null){
            return;
        }
        Unit workingUnit = dominatorsFinder.getImmediateDominator(unitOfStartMethod);
        BundlesPropagatorSwitch bundlesPropagatorSwitch = new BundlesPropagatorSwitch(currentSootMethod, registerToTrack);
        while (workingUnit != null && !bundlesPropagatorSwitch.isDone()){
            workingUnit.apply(bundlesPropagatorSwitch);
            workingUnit = dominatorsFinder.getImmediateDominator(workingUnit);
        }

    }
}
