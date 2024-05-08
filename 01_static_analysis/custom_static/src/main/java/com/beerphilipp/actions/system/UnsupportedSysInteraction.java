package com.beerphilipp.actions.system;

import com.fasterxml.jackson.annotation.JsonTypeName;
import lombok.Getter;
import lombok.Setter;

@JsonTypeName("unsupportedSysInteraction")
public class UnsupportedSysInteraction implements SysInteraction {

    @Getter
    @Setter
    String componentName;

    public UnsupportedSysInteraction(String componentName) {
        this.componentName = componentName;
    }
    @Override
    public String getType() {
        return "unsupportedSysInteraction";
    }
}
