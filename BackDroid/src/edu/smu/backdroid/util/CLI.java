package edu.smu.backdroid.util;

import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

/**
 * A simple Command Line Interface options manager.
 * 
 * @author Daoyuan
 * @since 13-04-26
 */
public class CLI {
    
    private Options options = new Options();
    
    public CLI() {
//        addOption(new Option("d", "dexdumplog", true, "the dexdump log of an apk"));
//        addOption(new Option("j", "dex2jarfile", true, "the dex2jar file of an apk"));
        addOption(new Option("a", "apkname", true, "the apk prefix name"));
        addOption(new Option("p", "pkgname", true, "the pkg name of an apk"));
        addOption(new Option("r", "release", true, "the release level"));
        addOption(new Option("t", "type", true, "the check type (CRYPTO or OpenPort)"));
    }
    
    private void addOption(Option option) {
        this.options.addOption(option);
    }
    
    public Options getOptions() {
        return options;
    }
}
