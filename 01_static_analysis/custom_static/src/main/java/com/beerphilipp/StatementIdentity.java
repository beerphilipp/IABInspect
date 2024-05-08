package com.beerphilipp;

import com.beerphilipp.util.SootUtil;
import lombok.Getter;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.UnitPatchingChain;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

public class StatementIdentity {

    @Getter
    private SootMethod method;
    @Getter
    private Unit unit;
    private final int unitNr;
    @Getter
    private final String uuid;

    public static StatementIdentity get(SootMethod method, Unit unit) {
        List<StatementIdentity> existingStatementIdentity = App.v().getAppContext().getStatementIdentities();

        synchronized (existingStatementIdentity) {
            for (StatementIdentity statementIdentity : existingStatementIdentity) {
                if (Objects.equals(statementIdentity.getMethod(), method) && Objects.equals(statementIdentity.getUnit(), unit)) {
                    return statementIdentity;
                }
            }
        }
        return new StatementIdentity(method, unit);
    }

    private StatementIdentity(SootMethod method, Unit unit) {
        this.method = method;
        this.unit = unit;
        this.unitNr = SootUtil.getUnitNrByUnit(method, unit);
        this.uuid = java.util.UUID.randomUUID().toString();
        App.v().getAppContext().addStatementIdentity(this);
    }

    /**
     * Because we change the Soot scene, we need to update the identity of the statement.
     */
    public void updateIdentity() {
        if (this.method.getSignature().startsWith("<dummyMainClass") || this.method.getSignature().startsWith("<entryClass")) {
            return;
        }
        this.method = Scene.v().getMethod(this.method.getSignature());
        this.unit = SootUtil.getUnitByNr(this.method, this.unitNr);
    }

    /**
     * Returns the StatementIdentity for the given method.
     * This method requires a Soot scene to be loaded.
     * @param sootMethod A string representation of the method.
     * @param unitMethod A string representation of the unit.
     * @param instructionId The instruction id of the unit.
     * @return The StatementIdentity for the given method or null if the method could not be found.
     */
    public static StatementIdentity getStatementIdentityByInstructionId(String sootMethod, String unitMethod, int instructionId) {
        SootMethod method = Scene.v().grabMethod(sootMethod);
        if (!method.hasActiveBody()) {
            method.retrieveActiveBody();
        }
        UnitPatchingChain units = method.getActiveBody().getUnits();
        int count = 0;
        for (Unit unit : units) {
            if (count == instructionId) {
                if (unit.toString().equals(unitMethod) ) {
                    return StatementIdentity.get(method, unit);
                }
                // This is a problem with ICCBot
                // TODO: Fix this issue!!!!
                return null;
                //assert false;
            }
            count++;
        }
        return null;
    }

    public void setUnit(Unit unit) {
        this.unit = unit;
    }

    @Override
    public String toString() {
        return "StatementIdentity{" +
                "method=" + method +
                ", unit=" + unit +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StatementIdentity that = (StatementIdentity) o;
        return Objects.equals(method, that.method) && Objects.equals(unit, that.unit);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, unit);
    }
}
