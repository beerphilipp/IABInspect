package com.beerphilipp.models.components;


import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public abstract class ComponentModel {

    protected String componentName;
    protected String exported;
    protected String permission;
    protected List<IntentFilterModel> intentFilterList;
    protected IntentData intentData;

    //protected IntentRecieveModel receiveModel;
    //protected IntentSendModel sendModel;

    //protected MisExposeModel misEAModel;


    public ComponentModel() {
        this.intentFilterList = new ArrayList<>();
    }

    public boolean isExported() {
        boolean action = false;
        for (IntentFilterModel intentFilterModel : intentFilterList) {
            if (!intentFilterModel.getActionList().isEmpty()) {
                action = true;
                break;
            }
        }
        if (exported != null && exported.equals("true"))
            return true;
        if (exported == null || exported.isEmpty())
            return !intentFilterList.isEmpty() && action;
        return false;
    }

    public void addIntentFilter(IntentFilterModel intentFilterModel) {
        intentFilterList.add(intentFilterModel);
    }
}
