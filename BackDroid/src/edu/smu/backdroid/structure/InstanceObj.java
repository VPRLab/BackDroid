package edu.smu.backdroid.structure;

import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;

import java.util.HashMap;
import java.util.Map;

import soot.SootClass;
import soot.util.Chain;

public class InstanceObj {

    private SootClass objclass;
    
    private Map<String, Object> objfields;

    public InstanceObj(SootClass objclass) {
        this.objclass = objclass;
        this.objfields = new HashMap<String, Object>();
    }

    public SootClass getObjClass() {
        return objclass;
    }

    public void setObjClass(SootClass objclass) {
        this.objclass = objclass;
    }

    public Map<String, Object> getObjFields() {
        return objfields;
    }

    // TODO a better representation?
    // For example, by using the construction point
    @Override
    public String toString() {
        Chain<SootClass> interfaces = objclass.getInterfaces();
        for (SootClass oneinterface : interfaces) {
            String interface_name = oneinterface.toString();
            // https://developer.android.com/reference/javax/net/ssl/HostnameVerifier.html
            if (interface_name.contains("HostnameVerifier")) {
                // (new com.xxx.HostNameVerifierWithCertificatePinning)[org.apache.http.conn.ssl.X509HostnameVerifier]
                return String.format("(new %s)[%s]", objclass.toString(), interface_name);
            }
        }
        
        return String.format("(new %s)", objclass.toString());
    }
    
    public void putOneFieldValue(String str_field, Object field_value) {
        this.objfields.put(str_field, field_value);
        
        MyUtil.printlnOutput(String.format("%s putOneFieldValue: %s.%s = %s",
                MyConstant.NormalPrefix, this.toString(), 
                str_field, (field_value != null) ? field_value.toString() : "null"),
                MyConstant.DEBUG);
    }
    
    public Object getOneFieldValue(String str_field) {
        Object result = this.objfields.get(str_field);
        
        MyUtil.printlnOutput(String.format("%s getOneFieldValue: %s.%s --> %s",
                MyConstant.NormalPrefix, this.toString(), 
                str_field, (result != null) ? result.toString() : "null"),
                MyConstant.DEBUG);
        
        return result;
    }
    
}
