package com.beerphilipp.icc.iccbot.mappings;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;

import java.util.List;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class ICCBotRoot {

    @JsonProperty("Component")
    @JacksonXmlElementWrapper(useWrapping = false)
    private List<ICCBotComponent> components;

    public List<ICCBotComponent> getComponents() {
        return components;
    }

    public void setComponents(List<ICCBotComponent> components) {
        this.components = components;
    }


    @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
    @JsonIgnoreProperties
    public static class ICCBotComponent {

        private String source;

        @JsonProperty("intentSummary")
        @JacksonXmlElementWrapper(useWrapping = false)
        List<ICCBotIntentSummary> intentSummaries;

        public String getSource() {
            return source;
        }

        public void setSource(String source) {
            this.source = source;
        }

        public List<ICCBotIntentSummary> getIntentSummaries() {
            return intentSummaries;
        }

        public void setIntentSummaries(List<ICCBotIntentSummary> intentSummaries) {
            this.intentSummaries = intentSummaries;
        }


        @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class ICCBotIntentSummary {

            @JsonProperty("source")
            private ICCBotSource source;

            @JsonProperty("destination")
            private ICCBotDestination destination;

            @JsonProperty("sendICCInfo")
            private ICCBotICCInfo sendICCInfo;

            @JsonProperty("receiveICCInfo")
            private ICCBotICCInfo receiveICCInfo;

            public ICCBotICCInfo getReceiveICCInfo() {
                return receiveICCInfo;
            }

            public void setReceiveICCInfo(ICCBotICCInfo receiveICCInfo) {
                this.receiveICCInfo = receiveICCInfo;
            }

            public ICCBotSource getSource() {
                return source;
            }

            public void setSource(ICCBotSource source) {
                this.source = source;
            }

            public ICCBotDestination getDestination() {
                return destination;
            }

            public void setDestination(ICCBotDestination destination) {
                this.destination = destination;
            }

            public ICCBotICCInfo getSendICCInfo() {
                return sendICCInfo;
            }

            public void setSendICCInfo(ICCBotICCInfo sendICCInfo) {
                this.sendICCInfo = sendICCInfo;
            }

            public static class ICCBotDestination {
                @JsonProperty("name")
                private String name;

                public String getName() {
                    return name;
                }

                public void setName(String name) {
                    this.name = name;
                }
            }

            public static class ICCBotSource {
                @JsonProperty("name")
                private String name;

                public String getName() {
                    return name;
                }

                public void setName(String name) {
                    this.name = name;
                }
            }

            @JsonIgnoreProperties(ignoreUnknown = true)
            public static class ICCBotICCInfo {

                @JsonProperty("extras")
                private String extras;

                private ICCBotInfo info;

                private String action;

                public String getAction() {
                    return action;
                }

                public void setAction(String action) {
                    this.action = action;
                }

                public String getExtras() {
                    return extras;
                }

                public void setExtras(String extras) {
                    this.extras = extras;
                }

                public ICCBotInfo getInfo() {
                    return info;
                }

                public void setInfo(ICCBotInfo info) {
                    this.info = info;
                }

                @JsonIgnoreProperties(ignoreUnknown = true)
                public static class ICCBotInfo {

                    private String unit;

                    private String methodSig;

                    private String instructionId;

                    public String getUnit() {
                        return unit;
                    }

                    public void setUnit(String unit) {
                        this.unit = unit;
                    }

                    public String getMethodSig() {
                        return methodSig;
                    }

                    public void setMethodSig(String methodSig) {
                        this.methodSig = methodSig;
                    }

                    public String getInstructionId() {
                        return instructionId;
                    }

                    public void setInstructionId(String instructionId) {
                        this.instructionId = instructionId;
                    }
                }

            }




        }




    }

}
