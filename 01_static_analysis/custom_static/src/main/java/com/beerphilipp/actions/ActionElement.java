package com.beerphilipp.actions;

import com.beerphilipp.actions.system.SysInteraction;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Data;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Data
public class ActionElement {

    @JsonSerialize(using = SootClassSerializer.class)
    private SootClass clazz;
    @JsonSerialize(using = SootMethodSerializer.class)
    private SootMethod method;
    @JsonIgnore
    private String actualActivity;
    private List<BranchInteraction> branchInteraction;
    private UIInteraction uiInteraction;
    private SysInteraction sysInteraction;

    public void addBranchInteraction(BranchInteraction branchInteraction) {
        if (this.branchInteraction == null) {
            this.branchInteraction = new ArrayList<>();
        }
        this.branchInteraction.add(branchInteraction);
    }

    public static class SootClassSerializer extends JsonSerializer<SootClass>
    {
        @Override
        public void serialize(SootClass sootClass, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            // TODO do the serialization properly. Think on what exactly we need
            jsonGenerator.writeObject(sootClass.toString());
        }
    }

    public static class SootMethodSerializer extends JsonSerializer<SootMethod>
    {
        @Override
        public void serialize(SootMethod sootMethod, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            // TODO do the serialization properly. Think on what exactly we need
            jsonGenerator.writeObject(sootMethod.toString());
        }
    }

    public static class UnitSerializer extends JsonSerializer<Unit>
    {
        @Override
        public void serialize(Unit unit, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            // TODO do the serialization properly. Think on what exactly we need
            jsonGenerator.writeObject(unit.toString());
        }
    }


}


