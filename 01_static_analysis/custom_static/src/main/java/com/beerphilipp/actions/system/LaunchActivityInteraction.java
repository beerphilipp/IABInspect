package com.beerphilipp.actions.system;

import com.fasterxml.jackson.annotation.JsonTypeName;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@JsonTypeName("launchActivity")
public class LaunchActivityInteraction implements SysInteraction {

    public LaunchActivityInteraction(String activityName) {
        this.activityName = activityName;
    }
    @Override
    public String getType() {
        return "launchActivity";
    }

    @Getter
    @Setter
    private String activityName;
    private Map<String, String> extras;
}
