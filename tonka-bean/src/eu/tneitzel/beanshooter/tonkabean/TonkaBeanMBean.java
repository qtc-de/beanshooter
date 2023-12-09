package eu.tneitzel.beanshooter.tonkabean;

import java.io.IOException;
import java.nio.file.InvalidPathException;

public interface TonkaBeanMBean
{
    public String version();
    public String[] shellInit();
    public String toServerDir(String current, String change) throws IOException, InvalidPathException;
    public byte[] downloadFile(String filename) throws IOException;
    public String uploadFile(String destination, String filename, byte[] content) throws IOException;
    public byte[] executeCommand(String[] cmd, String cwd, String[] env, boolean background) throws IOException, InterruptedException;
}
