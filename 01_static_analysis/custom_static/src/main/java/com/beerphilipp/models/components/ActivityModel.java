package com.beerphilipp.models.components;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ActivityModel extends ComponentModel {
    private String launchMode = "";
    private String taskAffinity;
    private String aliasFor;
}
