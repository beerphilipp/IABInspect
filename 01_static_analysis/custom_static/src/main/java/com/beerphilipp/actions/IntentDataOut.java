package com.beerphilipp.actions;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class IntentDataOut {
    private String data;
    private List<IntentExtraOut> extras = new ArrayList<>();

}
