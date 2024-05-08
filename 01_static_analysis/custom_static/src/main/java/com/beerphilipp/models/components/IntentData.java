package com.beerphilipp.models.components;

import lombok.Data;

import java.util.HashMap;

/**
 * This class is used to store the data and associated extras of an intent.
 */
@Data
public class IntentData {

    public IntentData(String data, HashMap<String, String> extras) {
        this.data = data;
        this.extras = extras;
    }

    private String data;
    private HashMap<String, String> extras;
}
