package com.beerphilipp.models.components;

import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
public class IntentFilterModel extends ComponentModel {
    private String priority = "0";
    private Set<String> actionList = new HashSet<>();
    private Set<String> categoryList = new HashSet<>();
    private Set<String> dataTypeList = new HashSet<>();
    private Set<IntentFilterData> dataList = new HashSet<>();
}
