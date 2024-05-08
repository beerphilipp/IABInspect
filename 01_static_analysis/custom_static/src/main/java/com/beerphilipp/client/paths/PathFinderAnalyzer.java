package com.beerphilipp.client.paths;

import com.beerphilipp.App;
import com.beerphilipp.CallChain;
import com.beerphilipp.Config;
import com.beerphilipp.StatementIdentity;
import com.beerphilipp.actions.ActionElement;
import com.beerphilipp.actions.ActionTarget;
import com.beerphilipp.actions.system.LaunchActivityInteraction;
import com.beerphilipp.actions.system.UnsupportedSysInteraction;
import com.beerphilipp.client.Analyzer;
import com.beerphilipp.client.instrumentation.branches.BranchConditionSet;
import com.beerphilipp.util.Input;
import soot.Scene;
import soot.SootMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

public class PathFinderAnalyzer extends Analyzer {

    @Override
    public void analyze() {

        List<String> excludeLibraries = Input.readFileAsList(Config.excludedLibraries);
        if (excludeLibraries == null) {
            throw new RuntimeException("Could not read excluded libraries file");
        }

        ControlFlowAnalysis controlFlowAnalysis = new ControlFlowAnalysis(appContext.getCallGraph());
        CallbackAnalysis callbackAnalysis = new CallbackAnalysis();

        List<ActionTarget> actionTargets = new ArrayList<>();

        for (StatementIdentity targetMethod : appContext.getTargetMethods()) {
            ActionTarget actionTarget = new ActionTarget();
            actionTarget.setToMethod(targetMethod.getMethod());
            actionTarget.setToStatement(targetMethod.getUnit());
            actionTarget.setUuid(targetMethod.getUuid());
            if (excludeLibraries.stream().anyMatch(excludedLibrary -> targetMethod.getMethod().getSignature().startsWith("<" + excludedLibrary))) {
                actionTarget.setIgnored(true);
            }
            if (!actionTarget.isIgnored()) {
                TargetPathFinder targetPathFinder = new TargetPathFinder(appContext.getCallGraph(), appContext.getResolvedEntryMethod(), appContext.getPartiallyResolvedEntryMethod());
                targetPathFinder.findTargetPaths(targetMethod);
                ArrayList<CallChain> resolvedPaths = targetPathFinder.getResolvedPaths();
                ArrayList<CallChain> partiallyResolvedPaths = targetPathFinder.getPartiallyResolvedPaths();
                ArrayList<CallChain> unresolvedPaths = targetPathFinder.getUnresolvedPaths();
                boolean isTimeout = targetPathFinder.isTimeout();
                actionTarget.setTimeout(isTimeout);

                for (CallChain callChain : resolvedPaths) {
                    List<ActionElement> path = createActionElements(controlFlowAnalysis, callbackAnalysis, callChain);
                    actionTarget.addResolvedPath(path);
                }

                for (CallChain callChain : partiallyResolvedPaths) {
                    List<ActionElement> path = createActionElements(controlFlowAnalysis, callbackAnalysis, callChain);
                    actionTarget.addPartiallyResolvedPath(path);
                }

                /*for (CallChain callChain : unresolvedPaths) {
                    List<ActionElement> path = createActionElements(controlFlowAnalysis, callbackAnalysis, callChain);
                    actionTarget.addUnresolvedPath(path);
                }*/
            }

            actionTargets.add(actionTarget);
        }

        appContext.setActionTargets(actionTargets);

        BranchConditionSet branchConditionSet = controlFlowAnalysis.getBranchconditionSet();
        appContext.setBranchConditionSet(branchConditionSet);

    }

    private List<ActionElement> createActionElements(ControlFlowAnalysis cfa, CallbackAnalysis cba, CallChain callChain) {
        List<ActionElement> path;
        path = cfa.analyzeControlFlow(callChain);
        path = cba.analyzeCallbacks(path);
        path = replaceDummyMethods(path);
        return path;
    }

    private List<ActionElement> replaceDummyMethods(List<ActionElement> path) {
        path.removeIf(actionElement -> actionElement.getMethod().getSignature().equals("<entryClass: void resolvedEntryMethod()>"));
        path.removeIf(actionElement -> actionElement.getMethod().getSignature().equals("<entryClass: void partiallyResolvedEntryMethod()>"));
        path.removeIf(actionElement -> actionElement.getMethod().getSignature().equals("<dummyMainClass: void dummyMainMethod(java.lang.String[])>"));

        // replace dummyMainMethods with onCreate methods. If there already is an onCreate in the path, we simply remove it
        ListIterator<ActionElement> iterator = path.listIterator();
        while (iterator.hasNext()) {
            ActionElement actionElement = iterator.next();
            boolean isDummyMainClass = actionElement.getMethod().getSignature().startsWith("<dummyMainClass");
            boolean isNextOnCreate = false;
            if (path.size() > iterator.nextIndex()) {
                isNextOnCreate = path.get(iterator.nextIndex()).getMethod().getSignature().endsWith("onCreate(android.os.Bundle)>");
            }
            if (isDummyMainClass && isNextOnCreate) {
                // remove the next element
                String returnType = actionElement.getMethod().getReturnType().toString();
                if (isActivity(returnType)) {
                    path.get(iterator.nextIndex()).setActualActivity(returnType);
                }
                iterator.remove();
            } else if (isDummyMainClass & !isNextOnCreate) {
                // replace iterator.next with a new ActionTarget.
                String returnType = actionElement.getMethod().getReturnType().toString();
                if (isActivity(returnType)) {
                    SootMethod onCreate = getOnCreateForActivity(returnType);
                    actionElement.setActualActivity(returnType);
                    actionElement.setMethod(onCreate);
                    actionElement.setClazz(onCreate.getDeclaringClass());
                }

            }
        }

        // add a system interaction to the first ActionElement if it is an onCreate method
        if (!path.isEmpty() && path.get(0).getMethod().getSignature().endsWith("onCreate(android.os.Bundle)>")) {
            ActionElement firstElement = path.get(0);
            String activity = firstElement.getActualActivity();
            if (activity == null) {
                // anything other than an activity is not supported at the moment
                firstElement.setSysInteraction(new UnsupportedSysInteraction(firstElement.getMethod().getReturnType().toString()));
            } else {
                firstElement.setSysInteraction(new LaunchActivityInteraction(activity));
            }
        }
        return path;
    }

    private boolean isActivity(String name) {
        return App.v().getAppContext().getActivityMap().containsKey(name);
    }



    private SootMethod getOnCreateForActivity(String activityName) {
        SootMethod onCreate = Scene.v().grabMethod("<" + activityName + ": void onCreate(android.os.Bundle)>");
        while (onCreate == null) {
            // get the superclass of the activity
            String superClassName = Scene.v().getSootClass(activityName).getSuperclass().getName();
            onCreate = Scene.v().grabMethod("<" + superClassName + ": void onCreate(android.os.Bundle)>");
            if (superClassName.equals("android.app.Activity")) {
                throw new RuntimeException("Could not find onCreate method for class " + activityName);
            }
        }
        return onCreate;
    }
}
