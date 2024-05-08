package com.beerphilipp.client.paths;

import com.beerphilipp.App;
import com.beerphilipp.actions.ActionElement;
import com.beerphilipp.actions.UIInteraction;
import com.beerphilipp.actions.system.SysInteraction;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.android.callbacks.AndroidCallbackDefinition;
import soot.util.MultiMap;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CallbackAnalysis {

    MultiMap<SootClass, AndroidCallbackDefinition> callbackMethods;

    public CallbackAnalysis() {
        this.callbackMethods = App.v().getAppContext().getCallbackMethods();
    }


    List<ActionElement> analyzeCallbacks(List<ActionElement> path) {
        for (int i = 0; i < path.size(); i++) {
            ActionElement actionElement = path.get(i);
            path.set(i, analyzeElement(actionElement));
        }
        return path;
    }


    private ActionElement analyzeElement(ActionElement actionElement) {
        SootMethod sootMethod = actionElement.getMethod();

        Set<AndroidCallbackDefinition> callbackDefinitions = new HashSet<>();
        for (SootClass clazz : this.callbackMethods.keySet()) {
            callbackDefinitions.addAll(this.callbackMethods.get(clazz));
        }
        if (callbackDefinitions != null) {
            for (AndroidCallbackDefinition definition : callbackDefinitions) {
                if (definition.getTargetMethod().equals(sootMethod)) {
                    if (definition.getCallbackType() == AndroidCallbackDefinition.CallbackType.Widget) {
                        UIInteraction uiInteraction = analyzeUIInteraction(definition);
                        actionElement.setUiInteraction(uiInteraction);
                    } else {
                        SysInteraction sysInteraction = analyzeSysInteraction(definition);
                        actionElement.setSysInteraction(sysInteraction);
                    }
                }
            }
        }
        return actionElement;
    }

    private UIInteraction analyzeUIInteraction(AndroidCallbackDefinition definition) {
        UIInteraction uiInteraction = new UIInteraction();

        if (definition.getParentMethod().getSignature().endsWith("onClick(android.view.View)>")) {
            uiInteraction.setResourceId("onClick");
        } else if (definition.getParentMethod().getSignature().endsWith("onTouch(android.view.View,android.view.MotionEvent)>")) {
            uiInteraction.setResourceId("onTouch");
        } else if (definition.getParentMethod().getSignature().endsWith("onItemClick(android.widget.AdapterView,android.view.View,int,long)>")) {
            uiInteraction.setResourceId("onClick");
        } else {
            uiInteraction.setResourceId("otherUIInteraction");
        }
        return uiInteraction;
    }

    private SysInteraction analyzeSysInteraction(AndroidCallbackDefinition definition) {
        return null;
    }
}
