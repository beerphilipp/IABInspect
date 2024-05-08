package com.beerphilipp.icc.iccbot.mappings;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import lombok.Data;

import java.util.List;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class ComponentInfo_Root {
    @JsonProperty("component")
    @JacksonXmlElementWrapper(useWrapping = false)
    private List<ComponentInfo_Component> components;
}
