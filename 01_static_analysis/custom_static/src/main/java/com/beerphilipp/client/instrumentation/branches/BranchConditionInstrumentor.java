package com.beerphilipp.client.instrumentation.branches;

import com.beerphilipp.client.instrumentation.Instrumentor;
import soot.*;
import soot.jimple.*;

import java.util.Iterator;
import java.util.List;

/**
 * This class is responsible for instrumenting the code to allow forcing of branches.
 */
public class BranchConditionInstrumentor implements Instrumentor {

    private final BranchConditionSet branchConditionSet;

    public BranchConditionInstrumentor(BranchConditionSet branchConditionSet) {
        this.branchConditionSet = branchConditionSet;
    }

    @Override
    public void instrument(Body body) {
        SootClass sootClass = body.getMethod().getDeclaringClass();
        SootMethod sootMethod = body.getMethod();

        if (branchConditionSet.getMethodSignatures().contains(body.getMethod().getSignature())) {
            // this method contains a branch that we want to force
            List<BranchConditionSet.BranchConditionEntry> entries = branchConditionSet.getEntriesForMethod(body.getMethod().getSignature());

            PatchingChain<Unit> units = body.getUnits();

            for (Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext(); ) {
                final Unit u = iter.next();

                if (u instanceof IfStmt) {
                    IfStmt ifStmt = (IfStmt) u;

                    for (BranchConditionSet.BranchConditionEntry entry: entries) {
                        if (u.equals(entry.getStatementIdentity().getUnit())) {
                            // Create a static variable in the class of the method
                            declareStaticBooleanVariable(sootClass, entry.getVariableName() + "_shouldForce");
                            declareStaticBooleanVariable(sootClass, entry.getVariableName() + "_forceTo");

                            setNewBranchCondition(sootClass, body, u, ifStmt, entry);
                        }
                    }
                }
            }
        }

    }

    private void setNewBranchCondition(SootClass sootClass, Body body, Unit currentUnit, IfStmt ifStmt, BranchConditionSet.BranchConditionEntry entry) {

        // We create local variables "..._local" based on the static variables "__bN_shouldForce" and "__bN_forceTo"
        Value staticShouldForce = Jimple.v().newStaticFieldRef(Scene.v().getField("<" + sootClass.toString() + ": boolean " + entry.getVariableName() + "_shouldForce" + ">").makeRef());
        Value staticForceTo = Jimple.v().newStaticFieldRef(Scene.v().getField("<" + sootClass.toString() + ": boolean " + entry.getVariableName() + "_forceTo" + ">").makeRef());

        Local shouldForceLocalVar = Jimple.v().newLocal(entry.getVariableName() + "_shouldForce_local", BooleanType.v());
        AssignStmt assignStmt = Jimple.v().newAssignStmt(shouldForceLocalVar, staticShouldForce);
        body.getLocals().add(shouldForceLocalVar);
        body.getUnits().insertBefore(assignStmt, currentUnit);

        Local forceToLocalVar = Jimple.v().newLocal(entry.getVariableName() + "_forceTo_local", BooleanType.v());
        AssignStmt assignStmt2 = Jimple.v().newAssignStmt(forceToLocalVar, staticForceTo);
        body.getLocals().add(forceToLocalVar);
        body.getUnits().insertBefore(assignStmt2, currentUnit);
        // Local variable creation done

        // We use nops to mark a specific position in the code
        Stmt originalIfFalseStart = Jimple.v().newNopStmt();
        body.getUnits().insertAfter(originalIfFalseStart, ifStmt);

        Stmt originalIfTrueStart = Jimple.v().newNopStmt();
        body.getUnits().insertBefore(originalIfTrueStart, ifStmt.getTarget());

        Stmt beforeOriginalIf = Jimple.v().newNopStmt();
        body.getUnits().insertBefore(beforeOriginalIf, ifStmt);

        Stmt beforeBeforeOriginalIf = Jimple.v().newNopStmt();
        body.getUnits().insertBefore(beforeBeforeOriginalIf, beforeOriginalIf);

        IfStmt ifShouldNotForceStmt = Jimple.v().newIfStmt(Jimple.v().newEqExpr(shouldForceLocalVar, IntConstant.v(0)), beforeOriginalIf); // this is shouldNotForce
        body.getUnits().insertBefore(ifShouldNotForceStmt, beforeBeforeOriginalIf);

        IfStmt ifForceTrueStmt = Jimple.v().newIfStmt(Jimple.v().newEqExpr(forceToLocalVar, IntConstant.v(1)), originalIfTrueStart); // this is forceTrue
        body.getUnits().insertBefore(ifForceTrueStmt, beforeBeforeOriginalIf);

        GotoStmt gotoStmt = Jimple.v().newGotoStmt(originalIfFalseStart);
        body.getUnits().insertBefore(gotoStmt, beforeBeforeOriginalIf);

        //OutputUtil.debug(body);
    }




    /**
     * Declares a static variable with the given name in the given class.
     * @param sootClass The class to declare the variable in
     * @param variableName The name of the variable
     */
    private void declareStaticBooleanVariable(SootClass sootClass, String variableName) {
        SootField field = new SootField(variableName, BooleanType.v(), Modifier.STATIC);
        sootClass.addField(field);
    }
}
