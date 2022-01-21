package de.qtc.beanshooter.tonkabean;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Map;
import java.util.Scanner;

/**
 * The TonkaBean is an example for a malicious MBean. When deployed on an MBeanServer, it allows
 * executing operating system commands and gives access to the file system of the server.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class TonkaBean implements TonkaBeanMBean
{
    /**
     * Checks whether the specified path is an existing directory on the server and returns
     * the normalized form of it.
     *
     * @param path file system path to check
     * @return normalized File
     */
    public File toServerDir(File path) throws IOException
    {
        if( !path.isDirectory() )
            throw new IOException("Specified path " + path.toString() + " is not a directory.");

        return path.getAbsoluteFile();
    }

    /**
     * Execute the specified operating system command. Commands need to be specified as an array with the
     * executable in the first position followed by the arguments for the call. Furthermore, the directory
     * to execute the command in and environment variables can be specified.
     *
     * @param command String array that specified the operating system command
     * @param cwd working directory for the call
     * @param env environment variables to use for the call
     */
    public String executeCommand(String[] command, File cwd, Map<String,String> env) throws IOException, InterruptedException
    {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(cwd);
        builder.environment().putAll(env);

        Process proc = builder.start();
        proc.waitFor();

        String output = "";

        try(Scanner scanner = new Scanner(proc.getInputStream()).useDelimiter("\\A"))
        {
            output += scanner.hasNext() ? scanner.next() : "";
            scanner.close();
        };

        try(Scanner scanner = new Scanner(proc.getErrorStream()).useDelimiter("\\A"))
        {
            output += scanner.hasNext() ? scanner.next() : "";
            scanner.close();
        }

        return output;
    }

    /**
     * Execute the specified operating system command in the background. Commands need to be specified as an array
     * with the executable in the first position followed by the arguments for the call. Furthermore, the directory
     * to execute the command in and environment variables can be specified.
     *
     * @param command String array that specified the operating system command
     * @param cwd working directory for the call
     * @param env environment variables to use for the call
     */
    public void executeCommandBackground(String[] command, File cwd, Map<String,String> env) throws IOException
    {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(cwd);
        builder.environment().putAll(env);
        builder.start();
    }

    /**
     * Verify that the MBean is working as expected by returning the string "pong!";
     *
     * @return static string "pong!"
     */
    public String ping()
    {
        return "pong!";
    }

    /**
     * Return the content of the specified file.
     *
     * @param filename file system path to the file to download
     * @return byte array containing the file content
     */
    public byte[] downloadFile(String filename) throws IOException
    {
        File file = new File(filename);
        return Files.readAllBytes(file.toPath());
    }

    /**
     * Write the specified byte array to the specified destination on the file system of the server.
     *
     * @param destination file system path on the MBean Server
     * @param content byte array containing the desired file content
     * @return resulting file system path of the newly generated file
     */
    public String uploadFile(String destination, byte[] content) throws IOException
    {
        File file = new File(destination);
        FileOutputStream stream = new FileOutputStream(destination);

        stream.write(content);
        stream.close();

        return file.getAbsolutePath();
    }
}
