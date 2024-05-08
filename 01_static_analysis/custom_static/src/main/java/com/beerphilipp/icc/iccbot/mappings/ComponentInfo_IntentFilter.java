package com.beerphilipp.icc.iccbot.mappings;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class ComponentInfo_IntentFilter {
    private String action;
    private String category;
    private String scheme;
}
