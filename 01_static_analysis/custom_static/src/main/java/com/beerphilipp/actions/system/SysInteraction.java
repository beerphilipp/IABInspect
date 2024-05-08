package com.beerphilipp.actions.system;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonSubTypes(
        {
                @JsonSubTypes.Type(value = LaunchActivityInteraction.class, name = "launchActivity"),
                @JsonSubTypes.Type(value = SysInteraction.class, name = "sysInteraction")
        }
)
@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY)
public interface SysInteraction {
    String getType();
}
