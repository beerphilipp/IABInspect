package com.beerphilipp.client.output;

import com.beerphilipp.ClientInfo;
import com.beerphilipp.client.Client;

/**
 * Writes the analysis results to the output.
 */
public class OutputClient extends Client {

        @Override
        protected void analyze() {
            OutputWriter outputWriter = new OutputWriter();
            outputWriter.start();
        }
}
