package edu.smu.backdroid.graph;

/**
 * An edge in BDG
 * 
 * @author Daoyuan
 * @since 13-04-06
 * @restart 17-06-06
 * @see AbstractEdge
 */
public class BDGEdge implements BDGEdgeType {
    
    private BDGUnit source;
    
    private BDGUnit target;
    
    /**
     * @see BDGEdgeType
     */
    private int type;

    public BDGEdge(BDGUnit source, BDGUnit target, int type) {
        this.source = source;
        this.target = target;
        this.type = type;
    }

    public BDGUnit getSource() {
        return source;
    }

    public void setSource(BDGUnit source) {
        this.source = source;
    }

    public BDGUnit getTarget() {
        return target;
    }

    public void setTarget(BDGUnit target) {
        this.target = target;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }
    
    /**
     * After implementing the hashCode(),
     * We can use it for contains() in a Set/List
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        
        BDGEdge other = (BDGEdge) obj;
        if (this.type != other.type)
            return false;
        if (!this.source.equals(other.source))
            return false;
        if (!this.target.equals(other.target))
            return false;
        
        return true;
    }
    
    /**
     * For using contains() in Set/List
     * We must override this function
     * 
     * @see https://stackoverflow.com/a/17104610/197165
     * @see https://www.sitepoint.com/how-to-implement-javas-hashcode-correctly/
     * @see https://stackoverflow.com/questions/113511/best-implementation-for-hashcode-method
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((source == null) ? 0 : source.hashCode());
        result = prime * result + ((target == null) ? 0 : target.hashCode());
        result = prime * result + type;
        return result;
    }

    @Override
    public String toString() {
        return "BDGEdge [source=" + source + ", target=" + target + ", type=" + type + "]";
    }
    
}
