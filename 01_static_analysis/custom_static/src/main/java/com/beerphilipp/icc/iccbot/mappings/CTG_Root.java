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
public class CTG_Root {
    @JsonProperty("source")
    @JacksonXmlElementWrapper(useWrapping = false)
    private List<CTG_Source> sources;
}
