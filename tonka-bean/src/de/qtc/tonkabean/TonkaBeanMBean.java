package de.qtc.tonkabean;

import java.io.IOException;

public interface TonkaBeanMBean {

    public String ping();

    public void executeCommandBackground(String cmd) throws IOException;
    public String executeCommand(String cmd) throws IOException, InterruptedException ;

    public byte[] downloadFile(String filename) throws IOException;
    public void uploadFile(String destination, byte[] content) throws IOException;
}
