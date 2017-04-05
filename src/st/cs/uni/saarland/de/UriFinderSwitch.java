package st.cs.uni.saarland.de;

import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Created by avdiienko on 06/01/16.
 */
public class UriFinderSwitch extends AbstractStmtSwitch {
	  private boolean stop = false;
	    private Local localRegister;
	    private SootMethod currentMethod;
	    private String uri = null;

	    public String getUri(){
	        return uri;
	    }

	    public UriFinderSwitch(Local reg, SootMethod method){
	        this.localRegister = reg;
	        this.currentMethod = method;
	    }

	    public boolean isStop(){
	        return stop;
	    }


	    public void caseIdentityStmt(IdentityStmt stmt){
	        if(Thread.currentThread().isInterrupted()){
	            return;
	        }
	        if((stmt.getLeftOp() instanceof Local) && ((Local)stmt.getLeftOp()).equals(localRegister) && stmt.getRightOp() instanceof ParameterRef){
	            int index = ((ParameterRef)stmt.getRightOp()).getIndex();
	            findInReachableMethods(index, currentMethod, new ArrayList<SootMethod>());
	        }
	    }

	    public void caseAssignStmt(AssignStmt stmt){
	        processAssignStmt(stmt, currentMethod);
	    }

	    private void processAssignStmt(AssignStmt stmt, SootMethod currentSootMethod) {
	        if(Thread.currentThread().isInterrupted()){
	            return;
	        }
	        boolean containsInvokeExpr = stmt.containsInvokeExpr();

	        if(stmt.getLeftOp() instanceof Local && ((Local)stmt.getLeftOp()).equals(localRegister)){
	            if(!containsInvokeExpr){
	                if(stmt.getRightOp() instanceof CastExpr){
	                    localRegister = (Local)((CastExpr)stmt.getRightOp()).getOp();
	                }
	                else if(stmt.getRightOp() instanceof FieldRef){
	                    SootField field = ((FieldRef)stmt.getRightOp()).getField();
	                    try{
	                        String uri = field.getSignature();

	                        addToResults(uri);
	                        stop = true;
	                    }
	                    catch(java.lang.StringIndexOutOfBoundsException exc){
	                        System.err.println(stmt.toString());
	                    }
	                    return;
	                }
	                else if(stmt.getRightOp() instanceof Local){
	                    localRegister = (Local)stmt.getRightOp();
	                }
	                else if(stmt.getRightOp() instanceof ArrayRef){
	                    ArrayRef arr = (ArrayRef)stmt.getRightOp();
	                    if (arr.getIndex() instanceof IntConstant){
	                        localRegister = (Local)arr.getBase();
	                        int arrayIndex = ((IntConstant)arr.getIndex()).value;
	                        //Doesn't support for now
	                    }
	                }
	            }
	            else{//assume that Uri.Parse
	                InvokeExpr expr = stmt.getInvokeExpr();
	                SootMethod m = expr.getMethod();
	                if(m.getSignature().equals(CONTENT_RESOLVER_CONSTANTS.PARSE_URI)){
	                    Value param = expr.getArg(0);
	                    if(param instanceof Local){
	                        localRegister = (Local)param;
	                    }
	                    else if(param instanceof StringConstant){
	                        addToResults(((StringConstant)param).value);
	                        stop = true;
	                        return;
	                    }
	                }
	                else if(expr.getMethod().getSignature().equals(STRING_BUILDER_CONSTANTS.TO_STRING)){
	                    //we deal with a string builder
	                    Value registerToTrack = stmt.getInvokeExpr().getUseBoxes().get(stmt.getInvokeExpr().getUseBoxes().size() - 1).getValue();
	                    StringBuilderPropagator stringBuilderPropagator = new StringBuilderPropagator(currentSootMethod, stmt, registerToTrack);
	                    stringBuilderPropagator.run();
	                    String res = stringBuilderPropagator.getResult();
	                    if(res != null){
	                        addToResults(res);
	                    }
	                    stop = true;
	                    return;
	                }
	                else{
	                    findReturnValueInMethod(m);
	                }
	            }
	        }
	    }

	    private void findReturnValueInMethod(SootMethod m){
	        if(m.hasActiveBody()){
	            Body body = m.getActiveBody();
	            MHGDominatorsFinder<Unit> dominatorsFinder = new MHGDominatorsFinder<Unit>(new ExceptionalUnitGraph(body));
	            final PatchingChain<Unit> units = body.getUnits();
	            Unit currentUnit = units.getLast();
	            while(!Thread.currentThread().isInterrupted()){
	                currentUnit.apply(new AbstractStmtSwitch() {

	                    public void caseAssignStmt(AssignStmt stmt){
	                        processAssignStmt(stmt, m);
	                    }

	                    public void caseReturnStmt(ReturnStmt stmt){
	                        if(stmt.containsInvokeExpr()){
	                            SootMethod mInInvoke = stmt.getInvokeExpr().getMethod();
	                            findReturnValueInMethod(mInInvoke);
	                        }
	                        else{
	                            Value retValue = stmt.getOp();
	                            if(retValue instanceof StringConstant){
	                                String resValue = ((StringConstant)retValue).value;
	                                addToResults(resValue);
	                                stop = true;
	                                return;
	                            }
	                            else if(retValue instanceof Local){
	                                localRegister = (Local)retValue;
	                            }
	                        }
	                    }
	                });
	                if(dominatorsFinder.getImmediateDominator(currentUnit) == null || stop) break;
	                currentUnit = dominatorsFinder.getImmediateDominator(currentUnit);
	            }
	        }
	    }

	    private void findInReachableMethods(int argumentIndex, SootMethod method, List<SootMethod> callStack){
	        List<SootMethod> callStackInTheCurrentLevel = new ArrayList<SootMethod>();
	        callStackInTheCurrentLevel.addAll(callStack);

	        final Iterator<Edge> edgesToM = Scene.v().getCallGraph().edgesInto(method);

	        while(edgesToM.hasNext()){
	            final Edge e = edgesToM.next();
	            MethodOrMethodContext caller = e.getSrc();
	            Stmt stmt = e.srcStmt();

	            if(stmt.getInvokeExpr().getArg(argumentIndex) instanceof StringConstant){
	                addToResults(((StringConstant)stmt.getInvokeExpr().getArg(argumentIndex)).value);
	                continue;
	            }
	            if(!(stmt.getInvokeExpr().getArg(argumentIndex) instanceof Local)){
	                continue;
	            }

	            localRegister = (Local)stmt.getInvokeExpr().getArg(argumentIndex);
	            Body body = caller.method().getActiveBody();
	            Unit workingUnit = e.srcUnit();

	            //try to find where the value has been initialized
	            MHGDominatorsFinder<Unit> dominatorsFinder = new MHGDominatorsFinder<>(new ExceptionalUnitGraph(body));
	            while(dominatorsFinder.getImmediateDominator(workingUnit) != null && !stop && !Thread.currentThread().isInterrupted()){
	                workingUnit = dominatorsFinder.getImmediateDominator(workingUnit);

	                workingUnit.apply(new AbstractStmtSwitch() {

	                    public void caseIdentityStmt(IdentityStmt stmt)
	                    {
	                        //parameters: i0 := parameter0: int;
	                        //we should find the callers of the method ..
	                        if((stmt.getLeftOp() instanceof Local) && ((Local)stmt.getLeftOp()).equals(localRegister) && stmt.getRightOp() instanceof ParameterRef){
	                            ParameterRef pRef = (ParameterRef)stmt.getRightOp();
	                            int argumentIndex = pRef.getIndex();
	                            if(callStack.contains(caller.method())){
	                                return;
	                            }
	                            callStack.add(caller.method());
	                            findInReachableMethods(argumentIndex, caller.method(), callStack);
	                            callStack.clear();
	                            callStack.addAll(callStackInTheCurrentLevel);
	                        }
	                    }

	                    public void caseAssignStmt(AssignStmt stmt){
	                        processAssignStmt(stmt, caller.method());
	                    }
	                });
	            }
	        }
	    }
	    private void addToResults(String uri) {
	        this.uri = uri;
	    }
}