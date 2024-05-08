package com.beerphilipp.client.instrumentation.logging;

import com.beerphilipp.App;
import com.beerphilipp.StatementIdentity;
import com.beerphilipp.actions.ActionElement;
import com.beerphilipp.actions.ActionTarget;
import com.beerphilipp.client.instrumentation.Instrumentor;
import soot.*;
import soot.jimple.*;

import java.util.*;

public class LoggingInstrumentor implements Instrumentor {
    private final List<String> targetCallLocationSignatures = new ArrayList<>();
    private final List<StatementIdentity> targetStatements = App.v().getAppContext().getTargetMethods();

    private final List<SootMethod> methodsOnPath = new ArrayList<>();

    public LoggingInstrumentor(List<String> targetCallLocationSignatures) {
        this.targetCallLocationSignatures.addAll(targetCallLocationSignatures);
        saveMethodsOnPath();
    }

    private void saveMethodsOnPath() {
        List<ActionTarget> actionTargets = App.v().getAppContext().getActionTargets();
        for (ActionTarget actionTarget : actionTargets) {
            List<List<ActionElement>> actionElements = actionTarget.getResolvedPaths();
            List<List<ActionElement>> partiallyResolvedElements = actionTarget.getPartiallyResolvedPaths();
            List<List<ActionElement>> unresolvedActionElements = actionTarget.getUnresolvedPaths();
            List<List<ActionElement>> allActionElements = new ArrayList<>();
            allActionElements.addAll(actionElements);
            allActionElements.addAll(partiallyResolvedElements);
            allActionElements.addAll(unresolvedActionElements);
            for (List<ActionElement> actionElementList : allActionElements) {
                for (ActionElement actionElement : actionElementList) {
                    SootMethod sootMethod = actionElement.getMethod();
                    this.methodsOnPath.add(sootMethod);
                }
            }
        }
    }

    @Override
    public void instrument(Body body) {
        insertAtFunctionStart(body);
        insertBeforeWebViewCall(body);
    }

    private void insertAtFunctionStart(Body body) {
        SootMethod sootMethod = body.getMethod();

        SootMethod method = methodsOnPath.stream().filter(s -> s.getSignature().equals(sootMethod.getSignature())).findFirst().orElse(null);
        if (method == null) {
            return;
        }

        JimpleBody jimpleBody = (JimpleBody) body;
        createLoggingStatement(body, "33WV_METHOD44", "{\"type\": \"enterMethod\", \"method\": \"" + sootMethod.getSignature() + "\"}", jimpleBody.getFirstNonIdentityStmt());
    }

    private void insertBeforeWebViewCall(Body body) {
        SootMethod sootMethod = body.getMethod();
        PatchingChain<Unit> units = body.getUnits();

        // check if this method contains a WebView call
        StatementIdentity callStatement = targetStatements.stream().filter(s -> s.getMethod().equals(sootMethod)).findFirst().orElse(null);

        if (callStatement == null) {
            return;
        }

        for(Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
            final Unit u = iter.next();
            u.apply(new AbstractStmtSwitch() {
                public void caseInvokeStmt(InvokeStmt stmt) {
                    StatementIdentity statementIdentity = targetStatements.stream().filter(s -> s.getMethod().equals(sootMethod) && s.getUnit().equals(u)).findFirst().orElse(null);
                    if (statementIdentity != null) {
                        createLoggingStatement(body, "33WV_INSPECT44", "{\"type\": \"targetCall\", \"id\": \"" + statementIdentity.getUuid() + "\"}", u);
                        replaceUrlParameter(body, statementIdentity.getUuid(), stmt);
                    }
                }

            });
        }
    }

    private void replaceUrlParameter(Body body, String id, InvokeStmt stmt) {
        Value urlParameter = stmt.getInvokeExpr().getArg(0);
        StringConstant appendString = StringConstant.v("#" + id);

        // Create a new StringBuilder instance
        Local stringBuilderLocal = Jimple.v().newLocal("stringBuilder" + id.replace("-", ""), RefType.v("java.lang.StringBuilder"));
        body.getLocals().add(stringBuilderLocal);
        AssignStmt newStringBuilderStmt = Jimple.v().newAssignStmt(stringBuilderLocal, Jimple.v().newNewExpr(RefType.v("java.lang.StringBuilder")));
        body.getUnits().insertBefore(newStringBuilderStmt, stmt);
        InvokeStmt stringBuilderInitStmt = Jimple.v().newInvokeStmt(Jimple.v().newSpecialInvokeExpr(stringBuilderLocal, Scene.v().getMethod("<java.lang.StringBuilder: void <init>()>").makeRef()));
        body.getUnits().insertBefore(stringBuilderInitStmt, stmt);

        // Append original URL parameter
        InvokeExpr appendOriginalExpr = Jimple.v().newVirtualInvokeExpr(stringBuilderLocal, Scene.v().getMethod("<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>").makeRef(), List.of(urlParameter));
        AssignStmt appendOriginalStmt = Jimple.v().newAssignStmt(stringBuilderLocal, appendOriginalExpr);
        body.getUnits().insertBefore(appendOriginalStmt, stmt);

        // Append new parameter
        InvokeExpr appendNewExpr = Jimple.v().newVirtualInvokeExpr(stringBuilderLocal, Scene.v().getMethod("<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>").makeRef(), Arrays.asList(appendString));
        AssignStmt appendNewStmt = Jimple.v().newAssignStmt(stringBuilderLocal, appendNewExpr);
        body.getUnits().insertBefore(appendNewStmt, stmt);

        // Convert StringBuilder back to String
        Local resultStringLocal = Jimple.v().newLocal("resultString" + id.replace("-", ""), RefType.v("java.lang.String"));
        body.getLocals().add(resultStringLocal);
        InvokeExpr toStringExpr = Jimple.v().newVirtualInvokeExpr(stringBuilderLocal, Scene.v().getMethod("<java.lang.StringBuilder: java.lang.String toString()>").makeRef());
        AssignStmt toStringStmt = Jimple.v().newAssignStmt(resultStringLocal, toStringExpr);
        body.getUnits().insertBefore(toStringStmt, stmt);

        stmt.getInvokeExpr().setArg(0, resultStringLocal);
    }

    private SootField declareStaticStringVariable(SootClass sootClass, String variableName) {
        SootField field = new SootField(variableName, RefType.v("java.lang.String"), Modifier.STATIC);
        sootClass.addField(field);
        return field;
    }

    private Local createLocalVar(Body body, String name, Type type) {
        Local local = Jimple.v().newLocal(name, type);
        body.getLocals().add(local);
        return local;
    }

    private void createLoggingStatement(Body body, String tag, String content, Unit insertBefore) {
        PatchingChain<Unit> units = body.getUnits();
        Local tagLocal = Jimple.v().newLocal("_tagName__", RefType.v("java.lang.String"));
        body.getLocals().add(tagLocal);
        AssignStmt tagAssignStmt = Jimple.v().newAssignStmt(tagLocal, StringConstant.v(tag));
        units.insertBefore(tagAssignStmt, insertBefore);

        // Create the actual of the Log.d() call
        Local msgLocal = Jimple.v().newLocal("_msgName__", RefType.v("java.lang.String"));
        body.getLocals().add(msgLocal);
        AssignStmt msgAssignStmt = Jimple.v().newAssignStmt(msgLocal, StringConstant.v(content));
        units.insertAfter(msgAssignStmt, tagAssignStmt);

        // Create the Log.d() call
        Stmt logStartStmt = Jimple.v().newInvokeStmt(
                Jimple.v().newStaticInvokeExpr(
                        Scene.v().getSootClass("android.util.Log").getMethod("int i(java.lang.String,java.lang.String)").makeRef(),
                        tagLocal, msgLocal
                )
        );
        units.insertAfter(logStartStmt, msgAssignStmt);
    }
}
