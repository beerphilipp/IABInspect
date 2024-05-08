package com.beerphilipp.util;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;

public class SootUtil {

    public static SootClass getSootClassByName(String signature) {
        if (signature == null || signature.isEmpty())
            return null;
        try {
            for (SootClass sc : Scene.v().getApplicationClasses()) {
                if (sc.getName().equals(signature))
                    return sc;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Unit getUnitByNr(SootMethod sootMethod, int unitNr) {
        if (!sootMethod.hasActiveBody()) {
            sootMethod.retrieveActiveBody();
        }
        int count = 0;
        for (Unit u : sootMethod.getActiveBody().getUnits()) {
            if (count == unitNr) {
                return u;
            }
            count++;
        }
        return null;
    }

    /**
     * Returns the unit number of the given unit in the given method.
     * @param sootMethod The method.
     * @param unit The unit.
     * @return The unit number or -1 if the unit could not be found.
     */
    public static int getUnitNrByUnit(SootMethod sootMethod, Unit unit) {
        if (!sootMethod.hasActiveBody()) {
            sootMethod.retrieveActiveBody();
        }
        int count = 0;
        for (Unit u : sootMethod.getActiveBody().getUnits()) {
            if (u.equals(unit)) {
                return count;
            }
            count++;
        }
        return -1;
    }
}
