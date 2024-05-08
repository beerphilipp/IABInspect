package com.beerphilipp.client.paths;

import com.beerphilipp.CallChain;
import com.beerphilipp.Config;
import com.beerphilipp.StatementIdentity;
import com.beerphilipp.util.OutputUtil;
import lombok.Getter;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;

import com.beerphilipp.util.IteratorUtil;

/**
 *
 */
public class TargetPathFinder {
    // inspired by IntelliDroid and TIRO

    ArrayList<String> ignore = new ArrayList<>(Arrays.asList("<kotlin."));

    CallGraph callGraph;
    SootMethod resolvedEntryMethod;
    SootMethod partiallyResolvedEntryMethod;

    @Getter
    ArrayList<CallChain> resolvedPaths = new ArrayList<>();
    @Getter
    ArrayList<CallChain> partiallyResolvedPaths = new ArrayList<>();
    @Getter
    ArrayList<CallChain> unresolvedPaths = new ArrayList<>();
    @Getter
    boolean isTimeout = false;

    public TargetPathFinder(CallGraph callGraph, SootMethod resolvedEntryMethod, SootMethod partiallyResolvedEntryMethod) {
        this.callGraph = callGraph;
        this.resolvedEntryMethod = resolvedEntryMethod;
        this.partiallyResolvedEntryMethod = partiallyResolvedEntryMethod;
    }

    /**
     * Find all paths from the dummyMainMethod to the given target method.
     *
     * The algorithm works in a BFS manner. The search is performed in the reverse direction, i.e., starting at the target method
     * @param target The target method
     * @return
     */
    public void findTargetPaths(StatementIdentity target) {
        Instant now = Instant.now();
        OutputUtil.debug("Finding paths to " + target.getMethod());
        SootMethod targetMethod = target.getMethod();

        LinkedList<CallChain> stack = new LinkedList<>(); // This stack is used to store all the possible, not fully explored paths
        CallChain callChain = new CallChain(target);
        stack.push(callChain);

        while (!stack.isEmpty()) {
            Duration duration = Duration.between(now, Instant.now());
            if (duration.getSeconds() > Config.pathTimeout) {
                this.isTimeout = true;
                return;
            }
            CallChain currentPath = stack.pop();

            SootMethod currentMethod = currentPath.getLastElement().getMethod();

            if (currentMethod.equals(resolvedEntryMethod)) {
                // copy the current path
                CallChain resolvedPath = new CallChain(currentPath);
                resolvedPath.reverse();
                resolvedPaths.add(resolvedPath);

                if (resolvedPaths.size() > 100) {
                    //OutputUtil.alert("Found more than 100 resolved paths to " + targetMethod + ". We omit all future paths.");
                    return;
                }
                continue;
            }

            if (currentMethod.equals(partiallyResolvedEntryMethod)) {
                if (partiallyResolvedPaths.size() > 100) {
                    //OutputUtil.alert("Found more than 100 partially resolved paths to " + targetMethod + ". We do not save any more.");
                    continue;
                    //OutputUtil.alert("Found more than 100 partially resolved paths to " + targetMethod + ". We do not save any more.");
                } else {
                    CallChain partiallyResolvedPath = new CallChain(currentPath);
                    partiallyResolvedPath.reverse();
                    partiallyResolvedPaths.add(partiallyResolvedPath);
                }
            }

            if (currentPath.getNodes().size() > 150) {
                continue;
            }

            ArrayList<Edge> incomingEdges = IteratorUtil.iteratorToArrayList(callGraph.edgesInto(currentMethod));

            if (incomingEdges.isEmpty()) {
                // The node does not have an incoming edge.
                // We cannot reach this method from the dummy main method
                CallChain unresolvedCallChain = new CallChain(currentPath);
                unresolvedCallChain.reverse();
                unresolvedPaths.add(unresolvedCallChain);
            }

            for (Edge edge : incomingEdges) {
                CallChain newPath = new CallChain(currentPath);
                // check if the edge src is already in the call chain. if it is, we have a loop and discard the path
                if (newPath.contains(edge.src())) {
                    // The edge src is already in the call chain, i.e., we encountered a loop. Discard the path
                    continue;
                }
                if (edge.src() == null || edge.srcStmt() == null) {
                    continue;
                }
                // if the signature starts with any of the excluded libraries in the array "ignore", then ignore
                if (ignore.stream().anyMatch(excludedLibrary -> edge.src().getSignature().startsWith(excludedLibrary))) {
                    continue;
                }

                newPath.addNode(StatementIdentity.get(edge.src(), edge.srcStmt()));
                stack.add(newPath);
            }
        }
    }
}
