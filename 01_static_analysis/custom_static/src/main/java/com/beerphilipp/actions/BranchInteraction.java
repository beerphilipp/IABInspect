package com.beerphilipp.actions;

import lombok.Data;

@Data
public class BranchInteraction {

    private String variable;
    private boolean forceTo;

    public BranchInteraction(String variable, boolean forceTo) {
        this.variable = variable;
        this.forceTo = forceTo;
    }
}
