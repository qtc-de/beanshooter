package de.qtc.beanshooter.mbean.tonkabean;

import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.management.MBeanException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.mbean.MBeanInvocationHandler;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.utils.Utils;

/**
 * Dispatcher class for Tonka MBean operations. Implements operations that are supported
 * by the Tonka MBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private File cwd;
    private Map<String,String> env;
    private TonkaBeanMBean tonkaBean;

    /**
     * Creates the dispatcher that operates on the Tonka MBean.
     */
    public Dispatcher()
    {
        super(MBean.TONKA);
        cwd = new File(".");
        env = new HashMap<String,String>();

        if(BeanshooterOption.TARGET_HOST.isNull())
            return;

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        tonkaBean = (TonkaBeanMBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                            new Class<?>[] { TonkaBeanMBean.class },
                                                            invo);
    }


    /**
     * Dispatcher for the executeCommand action. Obtains the specified command from the command line and passes
     * it to the TokaBean on the remote MBeanServer. Optionally allows the current working directory and the
     * environment variables to be specified on the command line.
     */
    public void execute()
    {
        String command = ArgumentHandler.require(TonkaBeanOption.EXEC_CMD);
        String[] commandArray = Utils.splitSpaces(command, 1);

        File cwd = new File(TonkaBeanOption.EXEC_CWD.<String>getValue("."));
        Map<String,String> env = Utils.parseEnvironmentString(TonkaBeanOption.EXEC_ENV.<String>getValue(""));

        if( TonkaBeanOption.EXEC_RAW.getBool() )
            Logger.disableStdout();

        Logger.printMixedYellow("Invoking the", "executeCommand", "method with argument: ");
        Logger.printlnPlainBlue(String.join(" ", commandArray));

        try
        {
            byte[] result = tonkaBean.executeCommand(commandArray, cwd, env);

            Logger.printlnBlue("The call was successful");
            Logger.lineBreak();

            if( TonkaBeanOption.EXEC_HEX.getBool() )
            {
                Logger.printlnYellow("Server response:");
                System.out.println(Utils.bytesToHex(result));
            }

            else if( TonkaBeanOption.EXEC_FILE.notNull() )
            {
                try (FileOutputStream stream = new FileOutputStream(TonkaBeanOption.EXEC_FILE.<String>getValue()))
                {
                    stream.write(result);
                }

                Logger.printlnMixedYellow("Command output saved in", TonkaBeanOption.EXEC_FILE.<String>getValue());
            }

            else
            {
                Logger.printlnYellow("Server response:");
                System.out.write(result);
            }
        }

        catch (MBeanException e)
        {
            ExceptionHandler.handleMBeanGeneric(e);
            ExceptionHandler.handleExecException(e, commandArray);
        }

        catch( IOException e )
        {
            ExceptionHandler.handleFileWrite(e, TonkaBeanOption.EXEC_FILE.<String>getValue(), true);
        }
    }


    /**
     * Dispatcher for the executeCommandBackground action. Obtains the specified command from the command line and
     * passes it to the TokaBean on the remote MBeanServer. Optionally allows the current working directory and the
     * environment variables to be specified on the command line.
     */
    public void executeBackground()
    {
        String command = ArgumentHandler.require(TonkaBeanOption.EXEC_CMD);
        String[] commandArray = Utils.splitSpaces(command, 1);

        File cwd = new File(TonkaBeanOption.EXEC_CWD.<String>getValue("."));
        Map<String,String> env = Utils.parseEnvironmentString(TonkaBeanOption.EXEC_ENV.<String>getValue(""));

        Logger.printMixedYellow("Invoking the", "executeCommand", "method with argument: ");
        Logger.printlnPlainBlue(commandArray.toString());

        try
        {
            tonkaBean.executeCommandBackground(commandArray, cwd, env);
            Logger.printlnBlue("The call was successful");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.handleMBeanGeneric(e);
            ExceptionHandler.handleExecException(e, commandArray);
        }
    }

    /**
     * Dispatcher for the upload action. Reads a file from the local file system and uploads it to the remote
     * MBeanServer.
     */
    public void upload()
    {
        ArgumentHandler.requireAllOf(TonkaBeanOption.UPLOAD_DEST, TonkaBeanOption.UPLOAD_SOURCE);

        String uploadDest = TonkaBeanOption.UPLOAD_DEST.getValue();

        File uploadFile = new File(TonkaBeanOption.UPLOAD_SOURCE.<String>getValue());
        String uploadSrc = uploadFile.toPath().normalize().toAbsolutePath().toString();

        if( uploadDest.endsWith(File.separator) )
            uploadDest = uploadDest + uploadFile.getName();

        Logger.printMixedYellow("Uploading local file", uploadSrc, "to path ");
        Logger.printlnPlainMixedBlueFirst(uploadDest, "on the MBeanSerer.");

        try
        {
            byte[] content = Utils.readFile(uploadFile);
            tonkaBean.uploadFile(uploadDest, content);
            Logger.printlnMixedYellowFirst(content.length + " bytes", "uploaded successfully.");
        }

        catch ( MBeanException e)
        {
            ExceptionHandler.handleMBeanGeneric(e);
            ExceptionHandler.handleFileWrite(e, uploadDest, true);
        }

        catch (IOException e)
        {
            ExceptionHandler.handleFileRead(e, uploadSrc, true);
        }
    }

    /**
     * Dispatcher for the download action. Reads a file from the remote MBeanServer and saves it to the local
     * file system.
     */
    public void download()
    {
        ArgumentHandler.requireAllOf(TonkaBeanOption.DOWNLOAD_DEST, TonkaBeanOption.DOWNLOAD_SOURCE);

        String downloadDest = TonkaBeanOption.DOWNLOAD_DEST.<String>getValue();
        File downloadSrc = new File(TonkaBeanOption.DOWNLOAD_SOURCE.<String>getValue());

        File localFile = new File(downloadDest);

        if(localFile.isDirectory())
            localFile = Paths.get(downloadDest, downloadSrc.getName()).normalize().toFile();

        Logger.printMixedYellow("Saving remote file", downloadSrc.getPath(), "to local path ");
        Logger.printlnPlainBlue(localFile.getAbsolutePath());

        try {
            byte[] content = tonkaBean.downloadFile(downloadSrc.getPath());
            FileOutputStream stream = new FileOutputStream(localFile);

            stream.write(content);
            stream.close();

            Logger.printlnMixedYellowFirst(content.length + " bytes", "were written.");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.handleMBeanGeneric(e);
            ExceptionHandler.handleFileRead(e, downloadSrc.getPath(), true);
        }

        catch (IOException e)
        {
            ExceptionHandler.handleFileWrite(e, localFile.getAbsolutePath(), true);
        }
    }

    /**
     * Dispatcher for the shell action. Starts a do-while loop that reads shell commands from the user
     * and passes then to the handleShellCommand function.
     */
    public void shell()
    {
        String command;
        Console console = System.console();

        initCwd();
        String username = getUsername();
        String targetHost = BeanshooterOption.TARGET_HOST.getValue();

        do {
            Logger.printPlainMixedYellowFirst(String.format("[%s@%s", username, targetHost), cwd.getPath());
            Logger.printPlainYellow("]");
            Logger.printPlain("$ ");
            command = console.readLine();

        } while( handleShellCommand(command) );
    }

    /**
     * Handle the user specified shell command. This function parses the command and decides what to do
     * with it based on the first specified command item.
     *
     * @param command user specified command within the beanshooter shell
     * @return true if the shell should be kept open, false otherwise
     */
    private boolean handleShellCommand(String command)
    {
        if( command == null )
            return false;

        String[] commandArray = Utils.splitSpaces(command, 1);

        switch(commandArray[0])
        {
            case "exit":
            case "quit":
                return false;

            case "cd":
                if(commandArray.length > 1)
                    shellChangeDirectory(commandArray[1]);
                break;

            case "!background":
                shellCommandBackground(commandArray, cwd, env);
                break;

            case "!download":
                shellDownload(commandArray);
                break;

            case "!upload":
                shellUpload(commandArray);
                break;

            case "!env":
                env.putAll(Utils.parseEnvironmentString(command));
                break;

            case "!help":
                shellHelp();
                break;

            default:
                shellCommand(commandArray, cwd, env);
        }

        return true;
    }

    /**
     * Change the working directory of the shell. This call changes the local cwd variable stored within
     * the dispatcher and asks the remote MBeanServer whether the directory exists. If this is the case,
     * the change is applied, otherwise, the change is rejected with an error message.
     *
     * @param change requested directory change
     */
    private void shellChangeDirectory(String change)
    {
        File newCwd = new File(change);

        if( !newCwd.isAbsolute() )
            newCwd = Paths.get(cwd.getPath(), change).normalize().toFile();

        try
        {
            cwd = tonkaBean.toServerDir(newCwd);
        }

        catch (MBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof IOException )
                System.out.println(e.getMessage());

            else {
                Logger.printlnMixedYellow("Caught unexpected", t.getClass().getName(), "while changing directory.");
                ExceptionHandler.stackTrace(e);
            }
        }
    }

    /**
     * Execute the specified shell command in the background.
     *
     * @param commandArray command array to execute
     * @param cwd current working directory to operate in
     * @param env environment variables to use for the call
     */
    private void shellCommandBackground(String[] commandArray, File cwd, Map<String,String> env)
    {
        commandArray = Arrays.copyOfRange(commandArray, 1, commandArray.length);

        try
        {
            tonkaBean.executeCommandBackground(commandArray, cwd, env);
            System.out.println("Executing command in the background...");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.handleShellExecException(e, commandArray);
        }
    }

    /**
     * Execute the specified shell command and write the output to stdout.
     *
     * @param commandArray command array to execute
     * @param cwd current working directory to operate in
     * @param env environment variables to use for the call
     */
    private void shellCommand(String[] commandArray, File cwd, Map<String,String> env)
    {
        try
        {
            byte[] result = tonkaBean.executeCommand(commandArray, cwd, env);
            System.out.write(result);
        }

        catch (MBeanException e)
        {
            ExceptionHandler.handleShellExecException(e, commandArray);
        }

        catch (IOException e)
        {
            ExceptionHandler.unexpectedException(e, "writing", "command output", false);
        }
    }

    /**
     * Attempt to upload a file to the remote MBean server. This function is very similar to the ordinary
     * upload function, but the exception handling is adjusted to be more suitable for shell execution.
     *
     * @param arguments argument array obtained from the command line
     */
    private void shellUpload(String[] arguments)
    {
        if( arguments.length < 2 )
        {
            Logger.printlnPlain("usage: !upload <src> <dest>");
            return;
        }

        File source = new File(Utils.expandPath(arguments[1]));
        File destination = new File(source.getName());

        if( arguments.length > 2 )
            destination = new File(arguments[2]);

        if( !destination.isAbsolute() )
            destination = Paths.get(cwd.getPath(), destination.getPath()).toAbsolutePath().normalize().toFile();

        if( !source.isAbsolute() )
            source = Paths.get(".", source.getPath()).toAbsolutePath().normalize().toFile();

        try
        {
            byte[] content = Utils.readFile(source);
            tonkaBean.uploadFile(destination.getPath(), content);
            Logger.printlnPlainMixedYellowFirst(content.length + " bytes", "were written to", destination.getPath());
        }

        catch (MBeanException e)
        {
            ExceptionHandler.handleMBeanGeneric(e);
            ExceptionHandler.handleFileWrite(e, destination.getPath(), false);
        }

        catch (IOException e)
        {
            ExceptionHandler.handleFileRead(e, source.getPath(), false);
        }
    }

    /**
     * Attempt to download a file from the remote MBean server. This function is very similar to the ordinary
     * download function, but the exception handling is adjusted to be more suitable for shell execution.
     *
     * @param arguments argument array obtained from the command line
     */
    private void shellDownload(String[] arguments)
    {
        if( arguments.length < 2 )
        {
            System.out.println("usage: !download <src> <dest>");
            return;
        }

        File source = new File(arguments[1]);
        File destination = new File(source.getName());

        if( arguments.length > 2 )
            destination = new File(Utils.expandPath(arguments[2]));

        if( !source.isAbsolute() )
            source = Paths.get(cwd.getPath(), source.getPath()).toAbsolutePath().normalize().toFile();

        if( !destination.isAbsolute() )
            destination = Paths.get(".", destination.getPath()).toAbsolutePath().normalize().toFile();

        try
        {
            byte[] content = tonkaBean.downloadFile(source.getPath());
            FileOutputStream stream = new FileOutputStream(destination);

            stream.write(content);
            stream.close();

            Logger.printlnPlainMixedYellowFirst(content.length + " bytes", "were written to", destination.getPath());
        }

        catch (MBeanException e)
        {
            ExceptionHandler.handleMBeanGeneric(e);
            ExceptionHandler.handleFileRead(e, source.getPath(), false);
        }

        catch( IOException e )
        {
            ExceptionHandler.handleFileWrite(e, destination.getPath(), false);
        }
    }

    /**
     * Helper function to determine the username on shell startup.
     *
     * @return username the MBeanServer is running with
     */
    private String getUsername()
    {
        String username = "unknown";

        try {
            username = tonkaBean.username();

        } catch( MBeanException e ){}

        return username;
    }

    /**
     * Helper function to determine the current working directory on shell startup.
     */
    private void initCwd()
    {
        try {
             cwd = tonkaBean.toServerDir(cwd).toPath().normalize().toFile();

        } catch( MBeanException e ){}
    }

    /**
     * Print a help menu showing the supported shell commands.
     */
    private void shellHelp()
    {
        Logger.printlnPlainYellow("Available shell commands:");

        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  <cmd>", 30), "execute the specified command");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  cd <dir>", 30), "change working directory on the server");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  exit|quit", 30), "exit the shell");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !help", 30), "print this help menu");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !env <env-str>", 30), "set new environment variables in key=value format");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !upload <src> <dst>", 30), "upload a file to the remote MBeanServer");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !download <src> <dst>", 30), "download a file from the remote MBeanServer");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !background <cmd>", 30), "executes the specified command in the background");
    }
}
