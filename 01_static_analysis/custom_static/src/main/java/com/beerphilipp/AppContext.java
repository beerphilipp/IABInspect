package com.beerphilipp;

import com.beerphilipp.actions.ActionTarget;
import com.beerphilipp.client.instrumentation.branches.BranchConditionSet;
import com.beerphilipp.models.components.ComponentModel;
import lombok.Data;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.android.callbacks.AndroidCallbackDefinition;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.util.MultiMap;

import java.util.*;

@Data
public class AppContext {
    private String absolutePath;
    private String instrumentedApkPath;
    private String packageName;
    private CallGraph callGraph;
    private BranchConditionSet branchConditionSet;
    private List<ActionTarget> actionTargets;
    private Boolean isHybridApp;
    private SootMethod resolvedEntryMethod;
    private SootMethod partiallyResolvedEntryMethod;
    private List<StatementIdentity> targetMethods;

    private SootMethod dummyMainMethod;
    private String mainActivity;

    private HashMap<String, ComponentModel> componentMap = new HashMap<>();
    private HashMap<String, ComponentModel> activityMap = new HashMap<>();
    private HashMap<String, ComponentModel> serviceMap = new HashMap<>();
    private HashMap<String, ComponentModel> providerMap = new HashMap<>();
    private HashMap<String, ComponentModel> receiverMap = new HashMap<>();
    private HashMap<String, ComponentModel> exportedComponentMap = new HashMap<>();

    private Set<String> applicationClassNames = new HashSet<>();
    private Set<String> extendedPkgs = new HashSet<>();

    private boolean iccSuccess;
    private boolean intentExtractionSuccess;
    private boolean iccTimeout;
    private boolean onlyContainsExcludedMethods;

    private List<StatementIdentity> statementIdentities = Collections.synchronizedList(new ArrayList<>());

    private MultiMap<SootClass, AndroidCallbackDefinition> callbackMethods;

    private Exception exceptionOccurred;

    public void addStatementIdentity(StatementIdentity statementIdentity) {
        this.statementIdentities.add(statementIdentity);
    }

    public static AppContext getInstance2(String apkPath) {
        return new AppContext(apkPath);
    }

    private AppContext(String apkPath) {
        this.absolutePath = apkPath;
    }

    public void addToComponentMap(HashMap<String, ComponentModel> componentMap) {
        this.componentMap.putAll(componentMap);
    }

    public void addApplicationClassName(String className) {
        this.applicationClassNames.add(className);
    }

}
