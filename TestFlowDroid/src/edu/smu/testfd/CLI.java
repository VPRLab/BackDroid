package edu.smu.testfd;

import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

public class CLI {
    
    private Options options = new Options();
    
    public CLI() {
        addOption(new Option("a", "apk", true, "the apk path"));
    }
    
    private void addOption(Option option) {
        this.options.addOption(option);
    }
    
    public Options getOptions() {
        return options;
    }
}
