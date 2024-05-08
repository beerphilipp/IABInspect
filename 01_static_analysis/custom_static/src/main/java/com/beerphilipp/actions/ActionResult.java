package com.beerphilipp.actions;

import com.beerphilipp.models.components.ActivityModel;
import lombok.Data;

import java.util.List;

@Data
public class ActionResult {
    private String packageName;
    private String originalApkPath;
    private String instrumentedApkPath;
    private boolean isIccSuccess;
    private boolean isIntentExtrasSuccess;
    private List<ActionTarget> actionTargets;
    private boolean isHybridApp;
    private long manifestClientDuration;
    private long hybridAppClientDuration;
    private long pathClientDuration;
    private long callGraphClientDuration;
    private long iccClientDuration;
    private long pathFinderClientDuration;
    private long instrumentationClientDuration;
    private long totalDuration;
    private String exception;
    private List<ActivityOut> activities;
    private boolean iccTimeout;
}
