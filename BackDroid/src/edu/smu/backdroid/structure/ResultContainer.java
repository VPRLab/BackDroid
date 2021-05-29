package edu.smu.backdroid.structure;

import edu.smu.backdroid.util.MyConstant;

/**
 * The container for only one result
 * 
 * @author Daoyuan
 */
public class ResultContainer {
    
    /**
     * The ServerSocket init method signature
     */
    private String msig;
    
    private String params;
    
    /**
     * No longer for setting the TAG
     */
    private String tailmsig;
    
    /**
     * For finding similar SDKs
     * <com.kugou.android.mediatransfer.pctransfer.socket.a: void m()>
     * 
     * Now change it to:
     * "com.kugou.android.mediatransfer.pctransfer.socket.a"
     */
    private String initmsig;
    
    /**
     * For the USENIX paper, we use mark to flag "onClick"
     */
    private String mark;
    
    /**
     * TODO Added on 180901
     * True:  "LIVE"
     * False: "DEAD"
     */
    private boolean isLive;
    
    public ResultContainer() {
    }

    public String getMSig() {
        return msig;
    }

    public void setMSig(String msig) {
        this.msig = msig;
    }
    
    public String getTailMSig() {
        return tailmsig;
    }

    public void setTailMSig(String tailmsig) {
        this.tailmsig = tailmsig;
    }
    
    public String getInitMSig() {
        return initmsig;
    }

    public void setInitMSig(String initmsig) {
        this.initmsig = initmsig;
    }
    
    public String getMarkName() {
        return mark;
    }

    public void setMarkName(String mark) {
        this.mark = mark;
    }

    public String getParams() {
        return params;
    }

    public void setParams(String params) {
        this.params = params;
    }
    
    public boolean isLive() {
        return isLive;
    }

    public void setLive(boolean isLive) {
        this.isLive = isLive;
    }

    @Override
    public String toString() {
        String live_str;
        if (isLive)
            live_str = "LIVE";
        else
            live_str = "DEAD";
        
        return String.format("%s%s%s%s%s%s%s%s%s%s%s",
                live_str, MyConstant.MiddleWord,
                params, MyConstant.MiddleWord,
                initmsig, MyConstant.MiddleWord,
                tailmsig, MyConstant.MiddleWord,
                mark, MyConstant.MiddleWord,
                msig);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((initmsig == null) ? 0 : initmsig.hashCode());
        result = prime * result + (isLive ? 1231 : 1237);
        result = prime * result + ((mark == null) ? 0 : mark.hashCode());
        result = prime * result + ((msig == null) ? 0 : msig.hashCode());
        result = prime * result + ((params == null) ? 0 : params.hashCode());
        result = prime * result + ((tailmsig == null) ? 0 : tailmsig.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ResultContainer other = (ResultContainer) obj;
        if (initmsig == null) {
            if (other.initmsig != null)
                return false;
        } else if (!initmsig.equals(other.initmsig))
            return false;
        if (isLive != other.isLive)
            return false;
        if (mark == null) {
            if (other.mark != null)
                return false;
        } else if (!mark.equals(other.mark))
            return false;
        if (msig == null) {
            if (other.msig != null)
                return false;
        } else if (!msig.equals(other.msig))
            return false;
        if (params == null) {
            if (other.params != null)
                return false;
        } else if (!params.equals(other.params))
            return false;
        if (tailmsig == null) {
            if (other.tailmsig != null)
                return false;
        } else if (!tailmsig.equals(other.tailmsig))
            return false;
        return true;
    }

}
