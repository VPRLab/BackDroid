package edu.smu.backdroid.analysis;

import edu.smu.backdroid.PortDetector;
import edu.smu.backdroid.structure.ManifestComp;
import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ManifestWorker {
    
    private static ManifestWorker instance;
    
    /**
     * Typically it is "A: android:name".
     * That is: A: android:name(0x01010003)="" (Raw: "")
     * But could also be: A: :(0x01010003)="" (Raw: "")
     */
    private static String nameKeyWord = "(0x01010003)";
    
    static {
        ManifestWorker.instance = new ManifestWorker();
    }
    
    public static ManifestWorker v() {
        return ManifestWorker.instance;
    }
    
    private Set<String> rootClsSet;
    
    private List<ManifestComp> compList;
    
    private Set<String> maniCompSet;
    
    private Set<String> maniCompDexSet;
    
    public ManifestWorker() {
        rootClsSet = new HashSet<String>();
        compList = new ArrayList<ManifestComp>();
        maniCompSet = null;
        maniCompDexSet = null;
    }
    
    public boolean isAnalyzed() {
        return !rootClsSet.isEmpty();
    }
    
    /**
     * 1. Set package name
     * 2. Collect root class set
     * 3. Record entry components and their actions
     */
    public void runAnalysis() {
        // Search manifest
        String cmdcontent = String.format("aapt d xmltree %s AndroidManifest.xml " +
                "| grep -e \"A: package\" -e \"E: application\" " +
                "-e \"E: activity\" -e \"E: service\" " +
                "-e \"E: receiver\" -e \"E: provider\" " +
                "-e \"E: action\" -e \"E: category\" -e \"E: meta-data\" " +
                "-e \"%s\"", PortDetector.APKfile, nameKeyWord);
        MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                MyConstant.NormalPrefix, cmdcontent), MyConstant.DEBUG);
        
        // Analyze manifest output
        List<String> manifest_entries = MyUtil.grepCmdResult(cmdcontent, false);
        analyzeManifest(manifest_entries);
        
        // Output the result
        MyUtil.printlnOutput(String.format("%s ManifestWorker rootClsSet: %s",
                MyConstant.NormalPrefix, rootClsSet), MyConstant.WARN);
        MyUtil.printlnOutput(String.format("%s ManifestWorker compList: %s",
                MyConstant.NormalPrefix, compList), MyConstant.WARN);
    }
    
    private void analyzeManifest(List<String> manifest_entries) {
        
        int cur_mtype = MyConstant.MType_ERR;
        String cur_name = null;
        ManifestComp cur_comp = null;
        boolean is_action = false;
        boolean is_category = false;
        boolean is_metadata = false;
        
        for (String entry : manifest_entries) {
            if (entry.contains(nameKeyWord)) {
                if (!is_action && !is_category && !is_metadata) {
                    switch (cur_mtype) {
                        case MyConstant.MType_APP:
                        case MyConstant.MType_ACTIVITY:
                        case MyConstant.MType_SERVICE:
                        case MyConstant.MType_RECEIVER:
                        case MyConstant.MType_PROVIDER:
                            cur_name = getValuePerManifestEntry(entry, true);
                            cur_comp = new ManifestComp(cur_mtype, cur_name);
                            compList.add(cur_comp);
                            if (!cur_name.contains(PortDetector.PKGname))
                                rootClsSet.add(MyUtil.generateRootClsName(cur_name));
                            
                        case MyConstant.MType_PKG:
                        case MyConstant.MType_ERR:
                        default:
                            break;
                    }
                    
                } else if (is_action) {
                    // https://stackoverflow.com/questions/7080546/add-an-object-to-an-arraylist-and-modify-it-later
                    cur_comp.addAction(getValuePerManifestEntry(entry, false));
                }
                
            } else if (entry.contains("E: action")) {
                is_action = true;
                is_category = false;
                is_metadata = false;
                
            } else if (entry.contains("E: category")) {
                is_action = false;
                is_category = true;
                is_metadata = false;
                
            } else if (entry.contains("E: meta-data")) {
                is_action = false;
                is_category = false;
                is_metadata = true;
                
            } else if (entry.contains("E: activity")) {
                cur_mtype = MyConstant.MType_ACTIVITY;
                is_action = false;
                is_category = false;
                is_metadata = false;
                
            } else if (entry.contains("E: service")) {
                cur_mtype = MyConstant.MType_SERVICE;
                is_action = false;
                is_category = false;
                
            } else if (entry.contains("E: receiver")) {
                cur_mtype = MyConstant.MType_RECEIVER;
                is_action = false;
                is_category = false;
                is_metadata = false;
                
            } else if (entry.contains("E: provider")) {
                cur_mtype = MyConstant.MType_PROVIDER;
                is_action = false;
                is_category = false;
                is_metadata = false;
                
            } else if (entry.contains("E: application")) {
                cur_mtype = MyConstant.MType_APP;
                is_action = false;
                is_category = false;
                is_metadata = false;
                
            } else if (entry.contains("A: package")) {
                cur_mtype = MyConstant.MType_PKG;
                is_action = false;
                is_category = false;
                is_metadata = false;
                PortDetector.PKGname = getValuePerManifestEntry(entry, false);
                rootClsSet.add(PortDetector.PKGname);
            }
        }
    }
    
    private String getValuePerManifestEntry(String entry, boolean isComp) {
        String second_part = entry.split("Raw: \"")[1];
        String value = second_part.substring(0, second_part.length() - 2);
        
        // TODO but if really one word class?
        if (isComp) {
            if (value.startsWith("."))
                value = String.format("%s%s", PortDetector.PKGname, value);
            else if (!value.contains("."))
                value = String.format("%s.%s", PortDetector.PKGname, value);
        }
        
        return value;
    }
    
    public Set<String> getRootClsSet() {
        return rootClsSet;
    }
    
    public Set<String> getManiCompSet() {
        if (!ManifestWorker.v().isAnalyzed())
            ManifestWorker.v().runAnalysis();
        
        if (maniCompSet == null)
            maniCompSet = new HashSet<String>();
        else
            return maniCompSet;
        
        for (ManifestComp comp : compList) {
            maniCompSet.add(comp.getName());
        }
        
        return maniCompSet;
    }
    
    public Set<String> getManiCompDexSet() {
        if (!ManifestWorker.v().isAnalyzed())
            ManifestWorker.v().runAnalysis();
        
        if (maniCompDexSet == null)
            maniCompDexSet = new HashSet<String>();
        else
            return maniCompDexSet;
        
        Set<String> maniCompSet = getManiCompSet();
        for (String manicomp_java : maniCompSet) {
            String manicomp_dex = MyUtil.transformIntoDexDumpValueType(manicomp_java);
            maniCompDexSet.add(manicomp_dex);
        }
        
        return maniCompDexSet;
    }

}
