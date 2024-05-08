package com.beerphilipp.models.analysis;

import lombok.Data;
import soot.SootMethod;
import soot.Unit;
import soot.Value;

@Data
public class StaticFieldInfo {

    public StaticFieldInfo(SootMethod method, Unit unit, Value value) {
        this.method = method;
        this.unit = unit;
        this.value = value;
    }

    private SootMethod method;
    private Unit unit;
    private Value value;
}
