package com.beerphilipp.client.callgraph;

import com.beerphilipp.client.Analyzer;
import com.beerphilipp.models.components.ComponentModel;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class CallGraphModifier extends Analyzer {

    CallGraph callGraph = appContext.getCallGraph();

    @Override
    public void analyze() {

        addNewEntryClass();
        addNewPartiallyResolvedEntryMethod();
        addNewResolvedEntryMethod();

        //addNewMainMethod();
        //addPartiallyResolvedEntryMethod();
    }

    private SootClass addNewEntryClass() {
        SootClass entryClass = Scene.v().makeSootClass("entryClass", Modifier.PUBLIC);
        entryClass.setSuperclass(Scene.v().getSootClass("java.lang.Object"));
        return entryClass;
    }

    private void addNewResolvedEntryMethod() {
        SootClass entryClass = Scene.v().getSootClass("entryClass");
        SootMethod resolvedEntryMethod = Scene.v().makeSootMethod("resolvedEntryMethod", List.of(new Type[]{}), VoidType.v(), Modifier.PUBLIC);
        entryClass.addMethod(resolvedEntryMethod);
        InvokeStmt entryMethodInvoke = addDummyInvoke(resolvedEntryMethod);

        List<String> exportedActivities = new ArrayList<>();
        HashMap<String, ComponentModel> allActivities = appContext.getActivityMap();
        for (String activity : allActivities.keySet()) {
            if (allActivities.get(activity).isExported()) {
                String componentName = allActivities.get(activity).getComponentName();
                exportedActivities.add(componentName);
            }
        }

        SootMethod dummyMainMethod = appContext.getDummyMainMethod();
        SootClass dummyMainClass = dummyMainMethod.getDeclaringClass();

        List<SootMethod> accessible = new ArrayList<>();
        for (SootMethod m : dummyMainClass.getMethods()) {
            if (m == dummyMainMethod) {
                continue;
            }
            // Create a new method in our entry class
            String returnType = m.getReturnType().toString();
            String activity = exportedActivities.stream().filter(a -> a.equals(returnType)).findAny().orElse(null);
            if (activity != null) {
                // This dummy method handles an activity
                accessible.add(m);
            } else {
                // TODO: We need to handle others as well
                /*String newMethodName = "undetermined_" + returnType.replace(".", "_");
                SootMethod newMethod = Scene.v().makeSootMethod(newMethodName, List.of(new Type[]{}), VoidType.v(), Modifier.PUBLIC);
                entryClass.addMethod(newMethod);*/
            }
        }

        for (SootMethod m : accessible) {
            // Add edges from the dummy main method to the new methods
            Edge edge = new Edge(resolvedEntryMethod, entryMethodInvoke, m);
            callGraph.addEdge(edge);
        }
        appContext.setResolvedEntryMethod(resolvedEntryMethod);


    }

    private void addNewPartiallyResolvedEntryMethod() {
        SootClass entryClass = Scene.v().getSootClass("entryClass");
        SootMethod partiallyResolvedEntryMethod = Scene.v().makeSootMethod("partiallyResolvedEntryMethod", List.of(new Type[]{}), VoidType.v(), Modifier.PUBLIC);
        entryClass.addMethod(partiallyResolvedEntryMethod);
        InvokeStmt entryMethodInvoke = addDummyInvoke(partiallyResolvedEntryMethod);

        List<String> allActivities = new ArrayList<>();
        HashMap<String, ComponentModel> activities = appContext.getActivityMap();
        for (String activity : activities.keySet()) {
            String componentName = activities.get(activity).getComponentName();
            allActivities.add(componentName);
        }

        SootMethod dummyMainMethod = appContext.getDummyMainMethod();
        SootClass dummyMainClass = dummyMainMethod.getDeclaringClass();

        List<SootMethod> accessible = new ArrayList<>();
        for (SootMethod m : dummyMainClass.getMethods()) {
            if (m == dummyMainMethod) {
                continue;
            }
            // Create a new method in our entry class
            String returnType = m.getReturnType().toString();
            String activity = allActivities.stream().filter(a -> a.equals(returnType)).findAny().orElse(null);
            if (activity != null) {
                // This dummy method handles an activity
                accessible.add(m);
            } else {
                // TODO: We need to handle others as well
            }
        }

        for (SootMethod m : accessible) {
            // Add edges from the dummy main method to the new methods
            Edge edge = new Edge(partiallyResolvedEntryMethod, entryMethodInvoke, m);
            callGraph.addEdge(edge);
        }
        appContext.setPartiallyResolvedEntryMethod(partiallyResolvedEntryMethod);
    }

    private InvokeStmt addDummyInvoke(SootMethod method) {
        JimpleBody body = Jimple.v().newBody(method);
        method.setActiveBody(body);
        UnitPatchingChain units = body.getUnits();

        Local tagLocal = Jimple.v().newLocal("_tagName__", RefType.v("java.lang.String"));
        body.getLocals().add(tagLocal);
        AssignStmt tagAssignStmt = Jimple.v().newAssignStmt(tagLocal, StringConstant.v("DUMMY"));
        units.add(tagAssignStmt);

        // Create the actual of the Log.d() call
        Local msgLocal = Jimple.v().newLocal("_msgName__", RefType.v("java.lang.String"));
        body.getLocals().add(msgLocal);
        AssignStmt msgAssignStmt = Jimple.v().newAssignStmt(msgLocal, StringConstant.v("DUMMY"));
        units.add(msgAssignStmt);

        // Create the Log.d() call
        InvokeStmt invokeStmt = Jimple.v().newInvokeStmt(
                Jimple.v().newStaticInvokeExpr(
                        Scene.v().getSootClass("android.util.Log").getMethod("int d(java.lang.String,java.lang.String)").makeRef(),
                        tagLocal, msgLocal
                )
        );
        units.add(invokeStmt);
        units.add(Jimple.v().newReturnVoidStmt());
        return invokeStmt;
    }



    public void addNewMainMethod() {
        SootClass entryClass = Scene.v().makeSootClass("entryClass", Modifier.PUBLIC);
        entryClass.setSuperclass(Scene.v().getSootClass("java.lang.Object"));
        SootMethod entryMethod = Scene.v().makeSootMethod("entryMethod", List.of(new Type[]{}), VoidType.v(), Modifier.PUBLIC);
        entryClass.addMethod(entryMethod);
        InvokeStmt entryMethodInvoke = addDummyInvoke(entryMethod);

        List<String> exportedActivities = new ArrayList<>();
        HashMap<String, ComponentModel> allActivities = appContext.getActivityMap();
        for (String activity : allActivities.keySet()) {
            if (allActivities.get(activity).isExported()) {
                String componentName = allActivities.get(activity).getComponentName();
                exportedActivities.add(componentName);
            }
        }

        SootMethod dummyMainMethod = appContext.getDummyMainMethod();
        SootClass dummyMainClass = dummyMainMethod.getDeclaringClass();

        List<SootMethod> accessible = new ArrayList<>();
        for (SootMethod m : dummyMainClass.getMethods()) {
            if (m == dummyMainMethod) {
                continue;
            }
            // Create a new method in our entry class
            String returnType = m.getReturnType().toString();
            String activity = exportedActivities.stream().filter(a -> a.equals(returnType)).findAny().orElse(null);
            if (activity != null) {
                // This dummy method handles an activity
                accessible.add(m);
            } else {
                // TODO: We need to handle others as well
                /*String newMethodName = "undetermined_" + returnType.replace(".", "_");
                SootMethod newMethod = Scene.v().makeSootMethod(newMethodName, List.of(new Type[]{}), VoidType.v(), Modifier.PUBLIC);
                entryClass.addMethod(newMethod);*/
            }
        }

        for (SootMethod m : accessible) {
            // Add edges from the dummy main method to the new methods
            Edge edge = new Edge(entryMethod, entryMethodInvoke, m);
            callGraph.addEdge(edge);
        }
        appContext.setResolvedEntryMethod(entryMethod);
    }
}
