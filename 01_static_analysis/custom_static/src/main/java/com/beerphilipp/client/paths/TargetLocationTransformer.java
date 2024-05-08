package com.beerphilipp.client.paths;

import com.beerphilipp.StatementIdentity;
import lombok.Getter;
import org.apache.logging.log4j.spi.CopyOnWrite;
import soot.*;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeStmt;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class TargetLocationTransformer extends BodyTransformer {

    private final List<String> targetMethodSignatures;

    @Getter
    private List<StatementIdentity> targetCallLocations = Collections.synchronizedList(new ArrayList<>());

    public TargetLocationTransformer(List<String> targetMethodSignatures) {
        this.targetMethodSignatures = targetMethodSignatures;
    }

    @Override
    protected void internalTransform(Body body, String s, Map<String, String> map) {
        // inspired by https://github.com/soot-oss/soot/wiki/Instrumenting-Android-Apps-with-Soot
        PatchingChain<Unit> units = body.getUnits();

        for(Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
            final Unit u = iter.next();

            u.apply(new AbstractStmtSwitch() {
                public void caseInvokeStmt(InvokeStmt stmt) {
                    String signature = stmt.getInvokeExpr().getMethod().getSignature();
                    if (targetMethodSignatures.contains(signature)) {
                        targetCallLocations.add(StatementIdentity.get(body.getMethod(), stmt));
                    }
                }

            });
        }
    }
}
