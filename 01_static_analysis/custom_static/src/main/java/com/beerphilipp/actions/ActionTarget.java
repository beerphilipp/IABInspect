package com.beerphilipp.actions;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Getter;
import lombok.Setter;
import soot.SootMethod;
import soot.Unit;

import java.util.ArrayList;
import java.util.List;

@Setter
@Getter
public class ActionTarget {

    @JsonSerialize(using = ActionElement.UnitSerializer.class)
    private Unit toStatement;
    @JsonSerialize(using = ActionElement.SootMethodSerializer.class)
    private SootMethod toMethod;
    private boolean ignored;
    private boolean isTimeout;
    private String uuid;
    private List<List<ActionElement>> resolvedPaths = new ArrayList<>();
    private List<List<ActionElement>> partiallyResolvedPaths = new ArrayList<>();
    private List<List<ActionElement>> unresolvedPaths = new ArrayList<>();

    public void addResolvedPath(List<ActionElement> path) {
        this.resolvedPaths.add(path);
    }

    public void addPartiallyResolvedPath(List<ActionElement> path) {
        this.partiallyResolvedPaths.add(path);
    }

    public void addUnresolvedPath(List<ActionElement> path) {
        this.unresolvedPaths.add(path);
    }
}
