package st.cs.uni.saarland.de;

import java.util.Set;

import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.AssignStmt;
import soot.jimple.CastExpr;
import soot.jimple.ClassConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.Stmt;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;

public class AnalyseIntentSwitch extends AbstractStmtSwitch {
    private Value registerOfIntent;
    private final SootMethod curentSootMethod;
    private boolean isDone = false;
    private final IntentInfo intentInfo;

    public boolean isDone(){
        return isDone;
    }

    public AnalyseIntentSwitch(Value register, SootMethod currentSootMethod, IntentInfo intentInfo){
        this.registerOfIntent = register;
        this.curentSootMethod = currentSootMethod;
        this.intentInfo = intentInfo;
    }

    public void caseAssignStmt(AssignStmt stmt){
        if(stmt.containsInvokeExpr()){
            processInvokeExpr(stmt);
            return;
        }

        if(stmt.getRightOp().equals(registerOfIntent)){
            //just reassignment
            registerOfIntent = stmt.getRightOp();
            return;
        }
        if(stmt.getRightOp() instanceof CastExpr){
            //just cast
            registerOfIntent = ((CastExpr) stmt.getRightOp()).getOp();
            return;
        }
    }

    public void caseInvokeStmt(InvokeStmt stmt){
        processInvokeExpr(stmt);
    }

    private void processInvokeExpr(Stmt stmt) {
        InvokeExpr invokeExpr = stmt.getInvokeExpr();
        if(invokeExpr instanceof StaticInvokeExpr)
            return;
        Value regsiterThatInvokes = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size() - 1).getValue();
        if(regsiterThatInvokes.equals(registerOfIntent) && regsiterThatInvokes.getType().toString().equals(START_ACTIVITY_CONSTANTS.INTENT_CLASS)){
            //check if we have method that sets something
            if(START_ACTIVITY_CONSTANTS.getIntentConstructors().contains(invokeExpr.getMethod().getSignature())){
                switch (invokeExpr.getMethod().getSignature()){
                    case START_ACTIVITY_CONSTANTS.INIT_DEFAULT:{
                        break;
                    }
                    case START_ACTIVITY_CONSTANTS.INIT_WITH_ACTION:{
                        processAction(stmt, invokeExpr, 0);
                        break;
                    }
                    case START_ACTIVITY_CONSTANTS.INIT_WITH_ACTION_URI:{
                        processAction(stmt, invokeExpr, 0);
                        processUri(stmt, invokeExpr, 1);
                        break;
                    }
                    case START_ACTIVITY_CONSTANTS.INIT_WITH_ACTION_URI_CONTEXT_CLASS:{
                        processAction(stmt, invokeExpr, 0);
                        processUri(stmt, invokeExpr, 1);
                        if(invokeExpr.getArg(2) instanceof ClassConstant) {
                            intentInfo.setClassName(((ClassConstant) invokeExpr.getArg(2)).getValue());
                        }
                        else{
                            processClass(stmt, invokeExpr, 2);
                        }
                        break;
                    }
                    case START_ACTIVITY_CONSTANTS.INIT_WITH_CONTEXT_CLASS:{
                        if(invokeExpr.getArg(1) instanceof ClassConstant) {
                            intentInfo.setClassName(((ClassConstant) invokeExpr.getArg(1)).getValue());
                        }
                        else{
                            processClass(stmt, invokeExpr, 1);
                        }
                        break;
                    }
                }
                //nothing to do. we rached a starting point of intents here
                isDone = true;
            }
            else{
                //just assignments
                switch (invokeExpr.getMethod().getSignature()){
                    case START_ACTIVITY_CONSTANTS.PUT_EXTRA:
                    case START_ACTIVITY_CONSTANTS.PUT_EXTRA2:{
                        StringPropagator stringPropagator = new StringPropagator(curentSootMethod, stmt, invokeExpr.getArg(0));
                        stringPropagator.run();
                        String extra = stringPropagator.getResult();
                        if(extra != null){
                            intentInfo.addExtra(extra);
                        }
                        break;
                    }
                    case START_ACTIVITY_CONSTANTS.PUT_EXTRAS_BUNDLE:{
                        BundlesPropagator bundlesPropagator = new BundlesPropagator(curentSootMethod, stmt, invokeExpr.getArg(0));
                        bundlesPropagator.run();
                        Set<String> extras = bundlesPropagator.getResults();
                        extras.forEach(intentInfo::addExtra);
                        break;
                    }
                    case START_ACTIVITY_CONSTANTS.SET_ACTION:{
                        processAction(stmt, invokeExpr, 0);
                        break;
                    }
                    case START_ACTIVITY_CONSTANTS.SET_CLASS:{
                        processClass(stmt, invokeExpr, 1);
                        break;
                    }
                    case START_ACTIVITY_CONSTANTS.SET_DATA_METHOD:{
                        processUri(stmt, invokeExpr, 0);
                        break;
                    }
                    case START_ACTIVITY_CONSTANTS.SET_COMPONENT:{
                        //analyze setComponent and find a target class
                        Value componentReg = invokeExpr.getArg(0);

                        MHGDominatorsFinder<Unit> dominatorsFinder = new MHGDominatorsFinder<>(new ExceptionalUnitGraph(curentSootMethod.getActiveBody()));
                        Unit curUnit = dominatorsFinder.getImmediateDominator(stmt);
                        AnalyzeComponentSwitch compSwitch = new AnalyzeComponentSwitch(componentReg, curentSootMethod);
                        while (curUnit != null){
                            curUnit.apply(compSwitch);
                            if(compSwitch.getResult() != null){
                                intentInfo.setClassName(compSwitch.getResult());
                                break;
                            }
                            curUnit = dominatorsFinder.getImmediateDominator(curUnit);
                        }

                        break;
                    }
                }
            }

        }
    }

    private void processClass(Stmt stmt, InvokeExpr invokeExpr, int paramNumber) {
        StringPropagator stringPropagator = new StringPropagator(curentSootMethod, stmt, invokeExpr.getArg(paramNumber));
        stringPropagator.run();
        String className = stringPropagator.getResult();
        if(className != null){
            intentInfo.setClassName(className);
        }
    }

    private void processUri(Stmt stmt, InvokeExpr invokeExpr, int paramNumber) {
        String uri = IntentHelper.analyzeInvokeExpressionToFindUris(curentSootMethod.getActiveBody(), stmt, invokeExpr.getMethod(), invokeExpr.getArg(paramNumber), false);
        if(uri != null){
            intentInfo.setData(uri);
        }
    }

    private void processAction(Stmt stmt, InvokeExpr invokeExpr, int paramNumber) {
        StringPropagator stringPropagator = new StringPropagator(curentSootMethod, stmt, invokeExpr.getArg(paramNumber));
        stringPropagator.run();
        String action = stringPropagator.getResult();
        if(action != null){
            intentInfo.setAction(action);
        }
    }
}