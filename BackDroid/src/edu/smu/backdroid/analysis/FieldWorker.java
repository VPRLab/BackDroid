package edu.smu.backdroid.analysis;

import edu.smu.backdroid.PortDetector;
import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Handle staffs related to global static fields
 * 
 * @author Daoyuan
 * @since 17-06-13
 */
public class FieldWorker {

    private static FieldWorker instance;
    
    private Map<String, Set<String>> fieldFuncMap;

    static {
        FieldWorker.instance = new FieldWorker();
    }
    
    public FieldWorker() {
        this.fieldFuncMap = new HashMap<String, Set<String>>();
    }
    
    /**
     * Get an instance of FieldWorker
     * 
     * @return
     */
    public static FieldWorker v() {
        return FieldWorker.instance;
    }

    /**
     * Search all funcs related to a static field
     * 
     * @param sootfield "<xcxin.filexpert.ftpserver.FTPServerService: int h>"
     */
    public void searchFieldFuncs(String sootfield) {
        //
        // If the key exists, it means we have added it before.
        // No need for analysis again
        //
        if (this.fieldFuncMap.containsKey(sootfield))
            return;
        
        Set<String> funcset = staticSearchFieldFuncs(sootfield);
        
        // add into the map
        this.fieldFuncMap.put(sootfield, funcset);
    }
    
    /**
     * 
     * @param sootfield
     * @return in dexdump format
     */
    public static Set<String> staticSearchFieldFuncs(final String sootfield) {
        /*
         * Need to transform SootField to DexDumpField format
         */
        String dexdumpfield = MyUtil.transformIntoDexDumpField(sootfield);
        dexdumpfield = MyUtil.sanitizeSS(dexdumpfield);
        
        /*
         * grep the fields
         */
        String cmdcontent = String.format("cat %s " +
                "| grep -e \"%s\" -e \".*:                                        |\\[.*\\] \" -e \"    #.* : (in L.*;)\" " +
                "| grep -B 2 -e \"%s\" " +
                "| grep -e \".*:                                        |\\[.*\\] \" -e \"    #.* : (in L.*;)\" ",
                PortDetector.DEXDUMPlog, dexdumpfield, dexdumpfield);
        MyUtil.printlnOutput(String.format("%s grep field: %s",
                MyConstant.ForwardPrefix, cmdcontent), MyConstant.DEBUG);
        
        // TODO return by grepMethodResult() is a list, not the set
        List<String> funclist = MyUtil.grepMethodResult(cmdcontent);
        Set<String> funcset = new HashSet<String>();
        for (String func_str : funclist) {
            funcset.add(func_str);
        }
        
        return funcset;
    }
    
    /**
     * Generate a set of field functions for the tainted field set
     * 
     * @param fieldset
     * @return
     */
    public Set<String> generateFieldFuncs(Set<String> fieldset) {
        Set<String> result = new HashSet<String>();
        
        for (String field : fieldset) {
            Set<String> funcset = this.fieldFuncMap.get(field);
            for (String func : funcset) {
                result.add(func);
            }
        }
        
        return result;
    }
    
}
