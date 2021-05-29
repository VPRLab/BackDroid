package edu.smu.backdroid.structure;

import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;

import java.util.HashMap;
import java.util.Map;

public class ArrayObj {
    
    /*
     * "newarray (int)[4]"
     */
    private String initsig;
    
    /*
     * TODO We use String to represent the index currently.
     * 
     * $r0[0] = 2609
     * -->
     * "0" --> 2609
     */
    private Map<String, Object> indexvalues;

    public ArrayObj(String initsig) {
        this.initsig = initsig;
        this.indexvalues = new HashMap<String, Object>();
    }

    public String getInitSig() {
        return initsig;
    }

    public void setInitSig(String initsig) {
        this.initsig = initsig;
    }
    
    // TODO better handle array object value
    @Override
    public String toString() {
        // Previously we need to represent byte[] IP address
//        if (indexvalues.containsKey("0")
//                || indexvalues.containsKey("1")
//                || indexvalues.containsKey("2")
//                || indexvalues.containsKey("3")) {
//            return String.format("\"%s.%s.%s.%s\"",
//                    indexvalues.get("0"),
//                    indexvalues.get("1"),
//                    indexvalues.get("2"),
//                    indexvalues.get("3"));
        if (indexvalues.isEmpty()) {
            return initsig;
            
        } else {
            StringBuilder sb = new StringBuilder("{");
            for (Map.Entry<String, Object> indexvalue : indexvalues.entrySet()) {
                String index = indexvalue.getKey();
                Object value = indexvalue.getValue();
                sb.append(String.format("[%s]=%s, ", index, value));
            }
            sb.append("}");
            
            return String.format("%s%s", initsig, sb.toString().replace(", }", "}"));
        }
    }
    
    public void putOneIndexValue(String str_index, Object index_value) {
        this.indexvalues.put(str_index, index_value);
        
        MyUtil.printlnOutput(String.format("%s putOneIndexValue: Array[%s] = %s",
                MyConstant.NormalPrefix,
                str_index, index_value.toString()),
                MyConstant.DEBUG);
    }
    
    public Object getOneIndexValue(String str_index) {
        Object result = this.indexvalues.get(str_index);
        
        if (result != null) {
            MyUtil.printlnOutput(String.format("%s getOneIndexValue: Array[%s] --> %s",
                    MyConstant.NormalPrefix,
                    str_index, result.toString()),
                    MyConstant.DEBUG);
        }
        
        return result;
    }

}
