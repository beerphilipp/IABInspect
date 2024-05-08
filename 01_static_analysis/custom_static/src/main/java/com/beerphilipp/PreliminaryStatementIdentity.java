package com.beerphilipp;

public class PreliminaryStatementIdentity {

    private String sootMethod;
    private String unit;

    private int lineNumber;

    public PreliminaryStatementIdentity(String sootMethod, String unit, int lineNumber) {
        this.sootMethod = sootMethod;
        this.unit = unit;
        this.lineNumber = lineNumber;
    }

    public String getSootMethod() {
        return sootMethod;
    }

    public String getUnit() {
        return unit;
    }

    public int getLineNumber() {
        return lineNumber;
    }
}
