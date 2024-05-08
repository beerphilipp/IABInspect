package com.beerphilipp.icc.iccbot.mappings;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import lombok.Data;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class ComponentInfo_Component {

    private String name;
    private String type;
    private boolean exported;

    @JsonProperty("manifest")
    @JacksonXmlElementWrapper(useWrapping = false)
    ComponentInfo_Manifest manifest;

    ComponentInfo_Receive receive;
    ComponentInfo_Sender sender;
}
