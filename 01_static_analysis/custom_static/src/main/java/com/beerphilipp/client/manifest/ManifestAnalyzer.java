package com.beerphilipp.client.manifest;

import com.beerphilipp.ClientInfo;
import com.beerphilipp.client.Analyzer;
import com.beerphilipp.models.components.*;
import com.beerphilipp.util.OutputUtil;
import com.beerphilipp.util.SootUtil;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.ProcessManifest;

import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

// Heavily based on ICCBot's ManifestAnalyzer.java
public class ManifestAnalyzer extends Analyzer {
    private ProcessManifest manifestManager;

    @Override
    public void analyze() {
        if (ClientInfo.getInstance().isFinished(ManagementFactory.class)) {
            return;
        }


        try {
            manifestManager = new ProcessManifest(appContext.getAbsolutePath());
        } catch (Exception e) {
            OutputUtil.error("No manifest is available");
            throw new RuntimeException("no manifest is available.");
        }

        String packageName = manifestManager.getPackageName();

        // the ".debug" will cause the imprecise of -exlib
        //if (pkg.endsWith(".debug"))
        //    pkg = pkg.replace(".debug", "");
        appContext.setPackageName(packageName);
        appContext.getExtendedPkgs().add(packageName);
        //appModel.getExtendedPakgs().add(pkg);
        //appModel.setVersionCode(manifestManager.getVersionCode());
        //appModel.setUsesPermissionSet(manifestManager.getPermissions());

        List<AXmlNode> activityNodes = new ArrayList<>(manifestManager.getAXml().getNodesWithTag("activity"));
        List<AXmlNode> aliasNodes = manifestManager.getAliasActivities();
        activityNodes.addAll(aliasNodes);
        parseComponent(activityNodes, "Activity");

        List<AXmlNode> serviceNodes = new ArrayList<>(manifestManager.getAXml().getNodesWithTag("service"));
        parseComponent(serviceNodes, "Service");

        List<AXmlNode> providerNodes = new ArrayList<>(manifestManager.getAXml().getNodesWithTag("provider"));
        parseComponent(providerNodes, "Provider");

        List<AXmlNode> receiverNodes = new ArrayList<>(manifestManager.getAXml().getNodesWithTag("receiver"));
        parseComponent(receiverNodes, "Receiver");

        mergeAllComponents();

        // Alias activities. This was changed.
        /*
        List<AXmlNode> alias = manifestManager.getAliasActivities();
        for (AXmlNode actNode : alias) {
            AXmlNode targetNode = manifestManager.getAliasActivityTarget(actNode);
            if (targetNode == null) {
                continue;
            }

            parseComponent(List.of(new AXmlNode[]{actNode}), "Activity");
            ActivityModel aliasActivityModel = (ActivityModel) appContext.getActivityMap().get(actNode.getAttribute("name").getValue().toString());
            String name = targetNode.getAttribute("name").getValue().toString();
            if (appContext.getActivityMap().containsKey(name)) {
                ActivityModel activityModel = (ActivityModel) appContext.getActivityMap().get(name);
                activityModel.addAlias(actNode.getAttribute("name").getValue().toString());
                analyzeIntentFilter(activityModel, actNode);
            }
        }
        */

        // Get the exported activities
        for (ComponentModel component : appContext.getComponentMap().values()) {
            if (component.isExported()) {
                appContext.getExportedComponentMap().put(component.getComponentName(), component);
            }
        }
    }

    private void parseComponent(List<AXmlNode> components, String type) {
        // get components
        HashMap<String, ComponentModel> componentMap = getComponentMap(type);
        for (AXmlNode componentNode : components) {
            // ignore the component whose "enabled" attribute is "false"
            if (componentNode.hasAttribute("enabled")) {
                if (componentNode.getAttribute("enabled").getValue().toString().isEmpty()
                        || componentNode.getAttribute("enabled").getValue().toString().equals("false")) {
                    continue;
                }
            }

            // new ActivityData instance
            if(!componentNode.hasAttribute("name")) continue;

            boolean isAlias = componentNode.getAttribute("targetActivity") != null;

            String componentName = componentNode.getAttribute("name").getValue().toString();
            if (!appContext.getApplicationClassNames().contains(componentName) & !isAlias) {
                if (!componentName.contains(appContext.getPackageName())) {
                    if (componentName.startsWith(".")) {
                        componentName = appContext.getPackageName() + componentName;
                    } else {
                        componentName = appContext.getPackageName() + "." + componentName;
                    }
                }
            }

            // add external libs according to component declaration
            if (!componentName.contains(appContext.getPackageName())) {
                String[] ss = componentName.split("\\.");
                if (ss.length >= 2)
                    appContext.getExtendedPkgs().add(ss[0] + "." + ss[1]);
            }
            ComponentModel componentModel = getComponentModel(type, componentName, isAlias);
            if (componentModel == null)
                continue;
            componentModel.setComponentName(componentName);

            synchronized (Objects.requireNonNull(componentMap)) {
                if (!componentMap.containsKey(componentModel.getComponentName())) {
                    componentMap.put(componentModel.getComponentName(), componentModel);
                }
            }

            if (componentModel instanceof ActivityModel & isAlias) {
                String targetActivity = componentNode.getAttribute("targetActivity").getValue().toString();
                ((ActivityModel)componentModel).setAliasFor(targetActivity);
            }

            // get the attributes of the activity element
            if (componentNode.getAttribute("exported") != null)
                componentModel.setExported(componentNode.getAttribute("exported").getValue().toString());

            if (componentNode.getAttribute("permission") != null)
                componentModel.setPermission(componentNode.getAttribute("permission").getValue().toString());

            if (componentModel instanceof ActivityModel && componentNode.getAttribute("launchMode") != null)
                ((ActivityModel) componentModel).setLaunchMode(componentNode.getAttribute("launchMode").getValue()
                        .toString());

            if (componentModel instanceof ActivityModel && componentNode.getAttribute("taskAffinity") != null)
                ((ActivityModel) componentModel).setTaskAffinity(componentNode.getAttribute("taskAffinity").getValue()
                        .toString());

            else if (componentModel instanceof ActivityModel)
                ((ActivityModel) componentModel).setTaskAffinity(appContext.getPackageName());

            analyzeIntentFilter(componentModel, componentNode);
        }

    }

    private void mergeAllComponents() {
        appContext.addToComponentMap(appContext.getActivityMap());
        appContext.addToComponentMap(appContext.getServiceMap());
        appContext.addToComponentMap(appContext.getProviderMap());
        appContext.addToComponentMap(appContext.getReceiverMap());
    }

    private HashMap<String, ComponentModel> getComponentMap(String type) {
        switch (type) {
            case "Activity":
                return appContext.getActivityMap();
            case "Service":
                return appContext.getServiceMap();
            case "Provider":
                return appContext.getProviderMap();
            case "Receiver":
                return appContext.getReceiverMap();
        }
        return null;
    }

    private ComponentModel getComponentModel(String type, String componentName, boolean isAlias) {
        if (SootUtil.getSootClassByName(componentName) == null & !isAlias)
            return null;
        switch (type) {
            case "Activity":
                if (appContext.getActivityMap().containsKey(componentName))
                    return appContext.getActivityMap().get(componentName);
                return new ActivityModel();
            case "Service":
                if (appContext.getServiceMap().containsKey(componentName))
                    return appContext.getServiceMap().get(componentName);
                return new ServiceModel();
            case "Receiver":
                if (appContext.getReceiverMap().containsKey(componentName))
                    return appContext.getReceiverMap().get(componentName);
                return new BroadcastReceiverModel();
        }
        return null;
    }

    private void analyzeIntentFilter(ComponentModel componentModel, AXmlNode componentNode) {
        // traverse the child elements of the activity element
        for (AXmlNode ifNode : componentNode.getChildren()) {
            if (ifNode.getTag().equals("intent-filter")) {
                // new IntentFilterData instance
                IntentFilterModel ifd = new IntentFilterModel();
                componentModel.addIntentFilter(ifd);
                if (ifNode.getAttribute("priority") != null)
                    ifd.setPriority(ifNode.getAttribute("priority").getValue().toString());

                // traverse child elements of the intent filter element
                for (AXmlNode childNode : ifNode.getChildren()) {
                    if (childNode.getTag().equals("action")) {
                        String action = childNode.getAttribute("name").getValue().toString();
                        ifd.getActionList().add(action);
                    }
                    if (childNode.getTag().equals("category")) {
                        String category = childNode.getAttribute("name").getValue().toString();
                        ifd.getCategoryList().add(category);
                    }
                    if (ifd.getActionList().contains("android.intent.action.MAIN")
                            && ifd.getCategoryList().contains("android.intent.category.LAUNCHER")) {
                        appContext.setMainActivity(componentModel.getComponentName());
                    }

                    if (childNode.getTag().equals("data")) {
                        IntentFilterData data = new IntentFilterData();
                        if (childNode.getAttribute("scheme") != null)
                            data.setScheme(childNode.getAttribute("scheme").getValue().toString());
                        if (childNode.getAttribute("host") != null)
                            data.setHost(childNode.getAttribute("host").getValue().toString());
                        if (childNode.getAttribute("port") != null) if (childNode.getAttribute("path") != null)
                            data.setPort(childNode.getAttribute("port").getValue().toString());
                        if (childNode.getAttribute("path") != null)
                            data.setPath(childNode.getAttribute("path").getValue().toString());
                        if (childNode.getAttribute("pathPattern") != null)
                            data.setPathPattern(childNode.getAttribute("pathPattern").getValue().toString());
                        if (childNode.getAttribute("pathPrefix") != null)
                            data.setPathPrefix(childNode.getAttribute("pathPrefix").getValue().toString());
                        if (childNode.getAttribute("pathSuffix") != null)
                            data.setPathSuffix(childNode.getAttribute("pathSuffix").getValue().toString());
                        if (childNode.getAttribute("pathAdvancedPattern") != null)
                            data.setPathAdvancedPattern(childNode.getAttribute("pathAdvancedPattern").getValue().toString());
                        if (childNode.getAttribute("mimeType") != null)
                            ifd.getDataTypeList().add(childNode.getAttribute("mimeType").getValue().toString());
                        if (!data.toString().isEmpty())
                            ifd.getDataList().add(data);
                    }
                }
            }
        }
    }
}

