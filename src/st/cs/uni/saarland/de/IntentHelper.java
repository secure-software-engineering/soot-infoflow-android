package st.cs.uni.saarland.de;

import java.util.HashSet;
import java.util.Set;

import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;

public class IntentHelper {
	private static Set<String> staticMethodSignatures;
	
	public static Set<String> getStaticMethodSignatures(){
		if(staticMethodSignatures == null){
	        staticMethodSignatures = new HashSet<>();
	        staticMethodSignatures.add(CONTENT_RESOLVER_CONSTANTS.QUERY);
	        staticMethodSignatures.add(CONTENT_RESOLVER_CONSTANTS.INSERT);
	        staticMethodSignatures.add(CONTENT_RESOLVER_CONSTANTS.BULKINSERT);
	        staticMethodSignatures.add(CONTENT_RESOLVER_CONSTANTS.UPDATE);
	        staticMethodSignatures.add(CONTENT_RESOLVER_CONSTANTS.DELETE);
		}
		return staticMethodSignatures;
	}
	
	public static String analyzeInvokeExpressionToFindUris(final Body b, final Unit u, SootMethod method, Value uriRegister, boolean isContentResolver) {

        if (!isContentResolver || getStaticMethodSignatures().contains(method.getSignature())) {

            if (!(uriRegister instanceof Local) && !(uriRegister.getType().equals("android.net.Uri")))
                return null;

            Local localRegister = (Local) uriRegister;

            MHGDominatorsFinder<Unit> dominatorsFinder = new MHGDominatorsFinder<Unit>(new ExceptionalUnitGraph(b));
            UriFinderSwitch uriSwitch = new UriFinderSwitch(localRegister, b.getMethod());

            Unit currentUnit = u;
            while (dominatorsFinder.getImmediateDominator(currentUnit) != null && !uriSwitch.isStop()) {
                currentUnit = dominatorsFinder.getImmediateDominator(currentUnit);
                currentUnit.apply(uriSwitch);
            }
            String uri = uriSwitch.getUri();
            if(uri != null){
                if(!isContentResolver){
                    return uri;
                }
                return method.getSignature().replace("(android.net.Uri,", String.format("(%s,", uri.replace("<","").replace(">","")));
            }
        }
        return null;
    }
}
