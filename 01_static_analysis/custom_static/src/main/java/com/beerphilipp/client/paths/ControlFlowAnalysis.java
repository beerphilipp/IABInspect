package com.beerphilipp.client.paths;

import com.beerphilipp.CallChain;
import com.beerphilipp.StatementIdentity;
import com.beerphilipp.actions.ActionElement;
import com.beerphilipp.actions.BranchInteraction;
import com.beerphilipp.actions.UIInteraction;
import com.beerphilipp.actions.system.SysInteraction;
import com.beerphilipp.client.instrumentation.branches.BranchConditionSet;
import com.beerphilipp.util.OutputUtil;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.toolkits.graph.BriefUnitGraph;

import java.util.ArrayList;
import java.util.List;

public class ControlFlowAnalysis {

    private CallGraph callGraph;
    private BranchConditionSet branchconditionSet;

    public ControlFlowAnalysis(CallGraph callGraph) {
        this.callGraph = callGraph;
        this.branchconditionSet = new BranchConditionSet();
    }

    public List<ActionElement> analyzeControlFlow(CallChain callChain) {
        List<ActionElement> path = new ArrayList<>();

        ArrayList<StatementIdentity> nodes = callChain.getNodes();
        for (StatementIdentity node: nodes) {
            ActionElement actionElement = test(node);
            if (actionElement != null) {
                path.add(actionElement);
            }
        }
        return path;
    }

    public BranchConditionSet getBranchconditionSet() {
        return branchconditionSet;
    }

    public ActionElement test(StatementIdentity callChainNode) {
        SootMethod sootMethod = callChainNode.getMethod();
        Unit stmt = callChainNode.getUnit();

        ActionElement actionElement = new ActionElement();
        actionElement.setClazz(callChainNode.getMethod().getDeclaringClass());
        actionElement.setMethod(sootMethod);

        if (callChainNode.getMethod().getSignature().startsWith("<dummyMainClass:")) {
            return actionElement;
        }

        Body body = sootMethod.getActiveBody();
        BriefUnitGraph cg = new BriefUnitGraph(body);

        Unit previousPred = stmt;

        List<Unit> preds = cg.getPredsOf(stmt);

        while (!preds.isEmpty()) {

            if (preds.size() > 1) {
                //OutputUtil.debug("More than one predecessor");
            }

            if (preds.size() == 1) {
                Unit pred = preds.get(0);

                if (pred instanceof IfStmt) {
                    // This is an if statement, and we NEED to take one of those branches to get to the statement
                    IfStmt ifStmt = (IfStmt) preds.get(0);

                    Unit falseBranch = cg.getSuccsOf(ifStmt).get(0);
                    Unit trueBranch = cg.getSuccsOf(ifStmt).get(1);

                    boolean forceTo;
                    if (trueBranch.equals(previousPred)) {
                        forceTo = true;
                    } else if (falseBranch.equals(previousPred)) {
                        forceTo = false;
                    } else {
                        throw new RuntimeException("This should not happen");
                    }
                    StatementIdentity statementIdentity = StatementIdentity.get(sootMethod, ifStmt);
                    String variableName = branchconditionSet.addBranching(statementIdentity, forceTo);
                    BranchInteraction branchInteraction = new BranchInteraction(variableName, forceTo);
                    actionElement.addBranchInteraction(branchInteraction);
                }

            }

            // There may be more than one predecessor. TODO find out if it is important to handle both predecessors.
            previousPred = preds.get(0);
            preds = cg.getPredsOf(preds.get(0));

        }

        /*List<List<Unit>> allPaths = new ArrayList<>();

        Stack<List<Unit>> stack = new Stack<>();

        List<Unit> initialPath = new ArrayList<>();
        initialPath.add(stmt);
        stack.push(initialPath);*/

        /*while (!stack.isEmpty()) {
            List<Unit> currentPath = stack.pop();
            List<Unit> currentPreds = cg.getPredsOf(currentPath.get(currentPath.size() - 1));

            if (currentPreds.isEmpty()) {
                // we have reached the beginning of the method
                allPaths.add(currentPath);
                continue;
            }

            for (Unit currentPred: currentPreds) {
                List<Unit> newPath = new ArrayList<>(currentPath);
                newPath.add(currentPred);
                stack.push(newPath);
            }

        }*/

        // print allpaths
        /*for (List<Unit> path: allPaths) {
            OutputUtil.debug("Path:");
            for (Unit unit: path) {
                OutputUtil.debug(unit.toString());
            }
        }*/








        /*preds = cg.getPredsOf(stmt);
        while (!preds.isEmpty()) {
            // we loop until we reach the beginning of the method
            // TODO We now always take the first occurrence. Also handle the case where there are multiple predecessors!
            Unit pred = preds.get(0);

            if (pred instanceof IfStmt) {
                // we have encountered an if statement. We need to figure out if this if statement needs to be set to true or false
                Unit falseBranch = cg.getSuccsOf(pred).get(0); // true branch
                Unit trueBranch = cg.getSuccsOf(pred).get(1); // false branch

                // We find out the position of this statement in the unitPatchingChain.
                // TODO: is this sorted in some way? Is it safe?
                // This is a dirty fix to find this if statement later on in the instrumentation phase.
                // We cannot match based on the branch condition itself, since different branches may have the same branch conditions.
                UnitPatchingChain unitPatchingChain = body.getUnits();
                int statementNumber = 0;
                for (Unit unit: unitPatchingChain) {
                    if (unit.equals(pred)) {
                        //OutputUtil.special(statementNumber);
                        break;
                    }
                    statementNumber++;
                }

                boolean forceTo;
                if (trueBranch.equals(previousPred)) {
                    forceTo = true;
                } else if (falseBranch.equals(previousPred)) {
                    forceTo = false;
                } else {
                    throw new RuntimeException("This should not happen");
                }

                IfStmt ifStmt = (IfStmt) pred;
                String variableName = branchconditionSet.addBranching(sootMethod, ifStmt, forceTo, statementNumber);
                BranchInteraction branchInteraction = new BranchInteraction(variableName, forceTo);
                actionElement.addBranchInteraction(branchInteraction);
            }
            previousPred = pred;
            preds = cg.getPredsOf(pred);
        }*/

        return actionElement;

    }


    /**
     * Creates a new condition that forces the if statement to be true or false.
     *
     * @param originalCondition The original condition of the if statement
     * @param forceTo True if the "if" statement should be forced to true, false otherwise
     * @param localVariableName The name of the local variable that should be used for the toggle condition
     * @return The new branch condition
     */
    private Value createForceBranchCondition(Value originalCondition, boolean forceTo, String localVariableName) {
        Value newOperand = Jimple.v().newLocal(localVariableName, BooleanType.v());
        OutputUtil.debug("newOperand: " + newOperand);
        if (forceTo) {
            // we need to force the if statement to be true
            Value modifiedOriginalCondition = Jimple.v().newNeExpr(originalCondition, IntConstant.v(0));
            Value newCondition = Jimple.v().newOrExpr(modifiedOriginalCondition, newOperand);
            return newCondition;
            //return Jimple.v().newOrExpr(originalCondition, newOperand);
        } else {
            return Jimple.v().newAndExpr(originalCondition, newOperand);
        }
    }
}
