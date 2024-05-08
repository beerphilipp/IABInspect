package com.beerphilipp.icc;

import com.beerphilipp.StatementIdentity;
import lombok.Data;

import java.util.List;

@Data
public class ICCEdge {
    private String sourceActivity;
    private StatementIdentity source;
    private String targetActivity;
    private List<String> extras;
}
