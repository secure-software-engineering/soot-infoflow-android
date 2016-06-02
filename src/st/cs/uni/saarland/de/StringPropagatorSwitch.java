package st.cs.uni.saarland.de;

import java.util.Iterator;
import java.util.Set;
import java.util.stream.Collectors;

import soot.Body;
import soot.Local;
import soot.MethodOrMethodContext;
import soot.Scene;
import soot.SootField;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.AssignStmt;
import soot.jimple.CastExpr;
import soot.jimple.ClassConstant;
import soot.jimple.FieldRef;
import soot.jimple.IdentityStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.ParameterRef;
import soot.jimple.ReturnStmt;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.toolkits.callgraph.Edge;
import soot.tagkit.StringConstantValueTag;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;

public class StringPropagatorSwitch extends AbstractStmtSwitch {
	private boolean isDone = false;
    private Value registerToTrack = null;
    private String result;
    private final SootMethod currentSootMethod;
    private final Set<SootMethod> callStack;

    private void addToResult(String toAdd){
        if(result == null || result.isEmpty()){
            result = toAdd;
        }
        else{
            result = (toAdd + "#" + result);
        }
    }

    public String getResult(){
        return result;
    }

    public StringPropagatorSwitch(Value registerToTrack, SootMethod sootMethod, Set<SootMethod> callStack){
        this.registerToTrack = registerToTrack;
        this.currentSootMethod = sootMethod;
        this.callStack = callStack;
    }

    public boolean isDone(){
        return isDone;
    }

    public void caseAssignStmt(AssignStmt stmt){
        if(stmt.getLeftOp().equals(registerToTrack)){
            if(stmt.containsInvokeExpr()){
                if(stmt.getInvokeExpr() instanceof StaticInvokeExpr)
                    return;
                if(stmt.getInvokeExpr().getMethod().getSignature().equals(START_ACTIVITY_CONSTANTS.GET_CLASS)){
                    registerToTrack = stmt.getInvokeExpr().getUseBoxes().get(stmt.getInvokeExpr().getUseBoxes().size() - 1).getValue();
                    return;
                }
                if(stmt.getInvokeExpr().getMethod().getSignature().equals(STRING_BUILDER_CONSTANTS.TO_STRING)){
                    //we deal with a string builder
                    registerToTrack = stmt.getInvokeExpr().getUseBoxes().get(stmt.getInvokeExpr().getUseBoxes().size() - 1).getValue();
                    StringBuilderPropagator stringBuilderPropagator = new StringBuilderPropagator(currentSootMethod, stmt, registerToTrack);
                    stringBuilderPropagator.run();
                    String res = stringBuilderPropagator.getResult();
                    if(res != null){
                        addToResult(res);
                    }
                }
                processInvokeExpr(stmt.getInvokeExpr());
            }
            if(stmt.getRightOp() instanceof CastExpr){
                registerToTrack = ((CastExpr) stmt.getRightOp()).getOp();
                return;
            }
            if(stmt.getRightOp() instanceof ClassConstant){
                addToResult(((ClassConstant)stmt.getRightOp()).getValue());
                isDone = true;
                return;
            }
            if(stmt.containsFieldRef() && stmt.getRightOp() instanceof FieldRef){
                SootField f = ((FieldRef)stmt.getRightOp()).getField();
                if(f.isStatic()) {
                    StringConstantValueTag tag = (StringConstantValueTag)f.getTag(StringConstantValueTag.class.getSimpleName());
                    if(tag != null) {
                        result = tag.getStringValue();
                        isDone = true;
                        return;
                    }
                }
            }
            registerToTrack = stmt.getRightOp();
        }
    }

    private void processInvokeExpr(InvokeExpr invokeExpr){
        findInReturnValue(invokeExpr.getMethod());
    }

    private void findInReturnValue(SootMethod methodToObserve){
        if(!methodToObserve.hasActiveBody()){
            isDone = true;
            return;
        }
        Set<Unit> returnStmts = methodToObserve.getActiveBody().getUnits().stream().
                filter(u-> u instanceof ReturnStmt).collect(Collectors.toSet());
        MHGDominatorsFinder<Unit> dominatorsFinder = new MHGDominatorsFinder<>(new ExceptionalUnitGraph(methodToObserve.getActiveBody()));
        for(Unit retStmt : returnStmts){
            ReturnStmt returnStmt = (ReturnStmt)retStmt;
            Value register = returnStmt.getOp();
            if(register instanceof StringConstant){
                addToResult(((StringConstant)register).value);
                isDone = true;
                return;
            }
            Unit currentUnit = retStmt;
            StringPropagatorSwitch internalStringPropagator = new StringPropagatorSwitch(register, currentSootMethod, callStack);
            while(currentUnit != null && internalStringPropagator.isDone()){
                currentUnit.apply(internalStringPropagator);
                currentUnit = dominatorsFinder.getImmediateDominator(currentUnit);
            }
            addToResult(internalStringPropagator.getResult());
        }
        isDone = true;
    }

    public void caseIdentityStmt(IdentityStmt stmt){
        if(stmt.getLeftOp().equals(registerToTrack) && stmt.getRightOp() instanceof ParameterRef){
            ParameterRef parameterRef = (ParameterRef)stmt.getRightOp();
            findInReachableMethods(currentSootMethod, parameterRef.getIndex());
        }
    }

    private void findInReachableMethods(SootMethod method, int argumentIndex){
        if(callStack.contains(method)){
            return;
        }
        callStack.add(method);
        final Iterator<Edge> edgesToM = Scene.v().getCallGraph().edgesInto(method);

        while(edgesToM.hasNext()) {
            final Edge e = edgesToM.next();
            MethodOrMethodContext caller = e.getSrc();
            Stmt stmt = e.srcStmt();

            if (stmt.getInvokeExpr().getArg(argumentIndex) instanceof StringConstant) {
                addToResult(((StringConstant) stmt.getInvokeExpr().getArg(argumentIndex)).value);
                isDone = true;
                continue;
            }
            if (!(stmt.getInvokeExpr().getArg(argumentIndex) instanceof Local)) {
                continue;
            }

            Value localRegister = stmt.getInvokeExpr().getArg(argumentIndex);
            Body body = caller.method().getActiveBody();
            Unit workingUnit = e.srcUnit();

            //try to find where the value has been initialized
            MHGDominatorsFinder<Unit> dominatorsFinder = new MHGDominatorsFinder<>(new ExceptionalUnitGraph(body));
            StringPropagatorSwitch internalStringSwitch = new StringPropagatorSwitch(localRegister, caller.method(), callStack);
            workingUnit = dominatorsFinder.getImmediateDominator(workingUnit);
            while(workingUnit != null && !internalStringSwitch.isDone()){
                workingUnit.apply(internalStringSwitch);
                workingUnit = dominatorsFinder.getImmediateDominator(workingUnit);
            }
            addToResult(internalStringSwitch.getResult());
            isDone = true;
        }
    }
}
