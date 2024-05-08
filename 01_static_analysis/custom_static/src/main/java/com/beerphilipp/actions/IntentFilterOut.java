package com.beerphilipp.actions;

import lombok.Data;

import java.util.List;

@Data
public class IntentFilterOut {
    private List<String> actions;
    private List<String> categories;
    private List<IntentFilterDataOut> data;

}
