package edu.smu.backdroid.graph;

/**
 * 
 * @author Daoyuan
 * @since 13-04-06
 * @see BDGEdge
 * @restart 17-06-06
 */
public interface BDGEdgeType {
    
    public static final int UNKNOWN_EDGE = -1;
    
    /**
     * direct edge in one method of CDG
     */
    public static final int DIRECT_EDGE = 0;
    
    /**
     * cross edge in CDG to connect different methods
     */
    public static final int CROSS_EDGE = 1;
    
    
    public static final int RETURN_EDGE = 2;
    
    
    public static final int SELFLOOP_EDGE = 3;

}
