package edu.smu.backdroid;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashSet;
import java.util.Set;

/**
 * Read android-classes.txt and generate android-classes.ser
 * 
 * @author Daoyuan
 * @see borrow some code from my VSinkDumper
 */
public class DumpAPIClass {
    
    public static String rootDirPath = 
            "../lib/";
    
    public static String textFilePath = 
            rootDirPath + "android-classes.txt";
    
    public static String dumpFilePath = 
            rootDirPath + "android-classes.ser";

    /**
     * @param args
     * @throws IOException 
     * @throws ClassNotFoundException 
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        Set<String> apiClassSet = new HashSet<String>();
        
        /*
         * Read file
         */
        BufferedReader filein = new BufferedReader(new FileReader(textFilePath));
        
        while (true) {
            String nextline = filein.readLine();
            if (nextline == null) //end of file
                break;
            
            apiClassSet.add(nextline);
        }
        
        if (filein != null)
            filein.close();
        
        /*
         * Dump to Serialize
         */
        FileOutputStream fileOut = new FileOutputStream(dumpFilePath);
        ObjectOutputStream out = new ObjectOutputStream(fileOut);
        out.writeObject(apiClassSet);
        System.out.println("Has dumped apiClassSet object into: "+dumpFilePath);
        out.close();
        fileOut.close();
        
        /*
         * test Deserialization and output logs
         */
        FileInputStream fileIn = new FileInputStream(dumpFilePath);
        ObjectInputStream in = new ObjectInputStream(fileIn);
        Set<String> outApiClass = (Set<String>) in.readObject();
        if (outApiClass.contains("org.apache.http.conn.ssl.SSLSocketFactory")
                && outApiClass.contains("android.graphics.Xfermode")
                && outApiClass.contains("javax.net.ssl.SSLContextSpi")) {
            System.out.println("outApiClass contains all tested classes.");
        }
        in.close();
        fileIn.close();
    }

}
