package com.beerphilipp.actions;

import lombok.Data;

@Data
public class IntentFilterDataOut {
    private String scheme;
    private String authority;
    private String path;
    private String mimeType;
}
