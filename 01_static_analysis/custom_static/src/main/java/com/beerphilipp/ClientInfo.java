package com.beerphilipp;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

@Data
public class ClientInfo {

    @Getter(value=AccessLevel.NONE)
    @Setter(value=AccessLevel.NONE)
    private static ClientInfo instance;

    public static ClientInfo getInstance() {
        if (instance == null) {
            instance = new ClientInfo();
        }
        return instance;
    }

    public static void reset() {
        instance = new ClientInfo();
    }

    private ClientInfo() { }

    private Map<String, Long> clientDurationMap = new HashMap<>();
    private Map<String, Long> analyzerDurationMap = new HashMap<>();
    private Map<String, Boolean> clientFinishedMap = new HashMap<>();
    private Map<String, Boolean> analyzerFinishedMap = new HashMap<>();

    public void setClientDuration(String clientName, long duration) {
        clientDurationMap.put(clientName, duration);
    }

    public void setAnalyzerDuration(String analyzerName, long duration) {
        analyzerDurationMap.put(analyzerName, duration);
    }

    public void setClientFinished(String clientName) {
        clientFinishedMap.put(clientName, true);
    }

    public void setAnalyzerFinished(String analyzerName) {
        analyzerFinishedMap.put(analyzerName, true);
    }

    public boolean isFinished(Class<?> tClass) {
        Boolean isFinishedClient = clientFinishedMap.get(tClass.getSimpleName());
        Boolean isFinishedAnalyzer = analyzerFinishedMap.get(tClass.getSimpleName());
        return Boolean.TRUE.equals(isFinishedAnalyzer) || Boolean.TRUE.equals(isFinishedClient);
    }


}
