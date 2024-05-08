package com.beerphilipp;

import lombok.Getter;
import lombok.Setter;
import soot.SootMethod;

import java.util.ArrayList;
import java.util.Collections;

public class CallChain {

    @Getter
    @Setter
    ArrayList<StatementIdentity> nodes;

    /**
     * Initializes a call chain with a single node
     * @param node Node to initialize the call chain with
     */
    public CallChain(StatementIdentity node) {
        this.nodes = new ArrayList<>();
        this.nodes.add(node);
    }


    /**
     * Create a CallChain from another CallChain
     * @param callChain CallChain to copy
     */
    public CallChain(CallChain callChain) {
        // create a deep copy of CallChain
        ArrayList<StatementIdentity> nodes = new ArrayList<>();
        for (StatementIdentity node : callChain.nodes) {
            nodes.add(StatementIdentity.get(node.getMethod(), node.getUnit()));
        }
        this.nodes = nodes;
    }

    public boolean isEmpty() {
        return nodes.isEmpty();
    }

    public StatementIdentity getLastElement() {
        return nodes.get(nodes.size() - 1);
    }

    public void addNode(StatementIdentity node) {
        nodes.add(node);
    }

    public void reverse() {
        Collections.reverse(nodes);
    }

    /**
     * Checks if the call chain contains the given method
     * @param method Method to check
     * @return true if the call chain contains the method, false otherwise
     */
    public boolean contains(SootMethod method) {
        return this.nodes.stream().anyMatch(node -> node.getMethod().equals(method));
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("CallChain: \n");
        for (StatementIdentity node : nodes) {
            stringBuilder.append(node.getMethod().getSignature()).append("\n");
        }
        return stringBuilder.toString();
    }
}
