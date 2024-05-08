package com.beerphilipp.client.instrumentation.branches;

import com.beerphilipp.StatementIdentity;
import lombok.Getter;
import soot.SootMethod;
import soot.Unit;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to hold information on identified branches and their conditions.
 */
public class BranchConditionSet {
    private ArrayList<BranchConditionEntry> entries = new ArrayList<>();

    public class BranchConditionEntry {
        @Getter
        private StatementIdentity statementIdentity;
        @Getter
        private boolean forceTo;
        @Getter
        private String variableName;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("<");
            sb.append("method: " + statementIdentity.getMethod().getSignature() + ", ");
            sb.append("statement: " + statementIdentity.getUnit() + ", ");
            sb.append("forceTo: " + forceTo + ", ");
            sb.append("variableName: " + variableName);
            sb.append(">");
            return sb.toString();
        }
    }

    /**
     * Adds a new branch to the set.
     * @param method
     * @param statement
     * @param forceTo
     * @return variableName
     */
    public String addBranching(StatementIdentity statementIdentity, boolean forceTo) {
        BranchConditionEntry entry = new BranchConditionEntry();
        entry.statementIdentity = statementIdentity;
        entry.forceTo = forceTo;
        entry.variableName = "__branchCondition" + entries.size();
        entries.add(entry);
        return entry.variableName;
    }

    /**
     * Returns the signature of the methods that contain branches that we want to force.
     * @return Array of method signatures
     */
    public List<String> getMethodSignatures() {
        ArrayList<String> methodSignatures = new ArrayList<>();
        for (BranchConditionEntry entry : entries) {
            String signature = entry.statementIdentity.getMethod().getSignature();
            if (!methodSignatures.contains(signature)) {
                methodSignatures.add(signature);
            }
        }
        return methodSignatures;
    }

    public List<SootMethod> getMethods() {
        ArrayList<SootMethod> methods = new ArrayList<>();
        for (BranchConditionEntry entry : entries) {
            if (!methods.contains(entry.statementIdentity.getMethod())) {
                methods.add(entry.statementIdentity.getMethod());
            }
        }
        return methods;
    }

    public List<String> getVariableNames() {
        ArrayList<String> variables = new ArrayList<>();
        for (BranchConditionEntry entry : entries) {
            if (!variables.contains(entry.variableName)) {
                variables.add(entry.variableName);
            }
        }
        return variables;
    }

    public List<BranchConditionSet.BranchConditionEntry> getEntriesForMethod(String methodSignature) {
        ArrayList<BranchConditionSet.BranchConditionEntry> entriesForMethod = new ArrayList<>();
        for (BranchConditionSet.BranchConditionEntry entry : entries) {
            if (entry.statementIdentity.getMethod().getSignature().equals(methodSignature)) {
                entriesForMethod.add(entry);
            }
        }
        return entriesForMethod;
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("BranchConditionSet: ");
        sb.append(entries.toString());
        return sb.toString();
    }
}
