package com.beerphilipp.icc.iccbot.mappings;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CTG_Destination {
    @JsonProperty("ICCType")
    private String iccType;
    private String name;
    private String desType;
    private String edgeType;
    private String method;
    private int instructionId;
    private String unit;
    private String extras;
    private String flags;
    private String action;
    private String category;
    private String type;
    private String data;
}
