package com.beerphilipp.actions;

import lombok.Data;

import java.util.List;

@Data
public class ActivityOut {
    private String name;
    private String aliasFor;
    private boolean exported;
    private List<IntentFilterOut> intentFilters;
    private IntentDataOut intent;

}
