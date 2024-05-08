package com.beerphilipp.models.components;

import lombok.Data;

@Data
public class IntentFilterData {
    /**
     * Represents the `<data>` element inside an `<intent-filter>` element.
     * See the <a href="https://developer.android.com/guide/topics/manifest/data-element">Android Developer Documentation</a>.
     */
    private String scheme;
    private String host;
    private String port;
    private String path;
    private String pathPattern;
    private String pathPrefix;
    private String pathSuffix;
    private String pathAdvancedPattern;
    private String mimeType;
}
