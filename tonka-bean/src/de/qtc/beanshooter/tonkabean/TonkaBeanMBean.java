package de.qtc.beanshooter.tonkabean;

import java.io.File;
import java.io.IOException;
import java.util.Map;

public interface TonkaBeanMBean
{
    public String ping();
    public File toServerDir(File cwd) throws IOException;

    public String executeCommand(String[] cmd, File cwd, Map<String,String> env) throws IOException, InterruptedException ;
    public void executeCommandBackground(String[] cmd, File cwd, Map<String,String> env) throws IOException ;

    public byte[] downloadFile(String filename) throws IOException;
    public String uploadFile(String destination, byte[] content) throws IOException;
}