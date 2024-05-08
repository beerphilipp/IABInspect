package com.beerphilipp.client.icc;

import com.beerphilipp.StatementIdentity;
import com.beerphilipp.client.Analyzer;
import com.beerphilipp.icc.ICCEdge;
import com.beerphilipp.icc.ICCExtraction;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.List;

public class ICCAnalyzer extends Analyzer {

    @Override
    public void analyze() {
        ICCExtraction iccExtraction = new ICCExtraction(appContext);
        List<ICCEdge> iccEdges = iccExtraction.extractICC();

        for (ICCEdge iccEdge : iccEdges) {
            addEdge(iccEdge.getSource(), iccEdge.getTargetActivity());
        }

        iccExtraction.extractIntentInformation();
    }

    private void addEdge(StatementIdentity source, String destinationActivity) {
        // We cannot directly find the onCreate method of the destination activity here, since 1) this may not be fully sufficient (stuff can be done in the onStart as well)
        // and 2) the activity may not have a direct onCreate method (if this is a subclass of another activity).
        // Instead, we add an edge to the dummy main method of the activity.
        String dummyDestinationMethod = String.format("<dummyMainClass: %s dummyMainMethod_%s(android.content.Intent)>", destinationActivity, destinationActivity.replace("_", "__").replace(".", "_"));
        SootMethod destinationOnCreateMethod = Scene.v().getMethod(dummyDestinationMethod);

        Edge edge = new Edge(source.getMethod(), (Stmt)source.getUnit(), destinationOnCreateMethod);
        appContext.getCallGraph().addEdge(edge);
    }
}
