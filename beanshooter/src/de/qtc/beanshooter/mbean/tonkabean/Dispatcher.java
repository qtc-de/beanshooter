package de.qtc.beanshooter.mbean.tonkabean;

import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.management.MBeanException;
import javax.management.RuntimeMBeanException;

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
    private String cwd;
    private Map<String,String> env;
    private TonkaBeanMBean tonkaBean;

    /**
     * Creates the dispatcher that operates on the Tonka MBean.
     */
    public Dispatcher()
    {
        super(MBean.TONKA);
        cwd = ".";
        env = new HashMap<String,String>();

        if(BeanshooterOption.TARGET_HOST.isNull())
            return;

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        tonkaBean = (TonkaBeanMBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                            new Class<?>[] { TonkaBeanMBean.class },
                                                            invo);
    }

    /**
     * Obtain the version from a deployed tonka bean and display it.
     */
    public void version()
    {
        try {
            Logger.printlnBlue(tonkaBean.version());

        } catch (MBeanException e) {
            ExceptionHandler.unexpectedException(e, "obtaining", "version", true);
        }
    }

    /**
     * Executes a command by obtaining the command string from the command line (EXEC_CMD) and splitting
     * it on spaces. The resulting list is passed to the TonkaBean and executed via ProcessBuilder. If
     * --shell was specified, the shell string is split and forms the initial command list. The specified
     * command is then appended as a single list argument to emulate a shell execution.
     *
     * This function is only a wrapper around the executeCommand function, which performs the actual
     * execution.
     */
    public void execute()
    {
        List<String> cmdList = new ArrayList<String>();
        String command = ArgumentHandler.require(TonkaBeanOption.EXEC_CMD);

        if (TonkaBeanOption.SHELL_CMD.notNull())
        {
            String shellStr = ArgumentHandler.require(TonkaBeanOption.SHELL_CMD);
            cmdList.addAll(Arrays.asList(Utils.splitSpaces(shellStr.trim(), 1)));
            cmdList.add(command);
        }

        else
            cmdList.addAll(Arrays.asList(Utils.splitSpaces(command, 1)));

        executeCommand(cmdList);
    }

    /**
     * Executes a command by obtaining a command array from the command line and passing it to the
     * TonkaBean. This method distinguishes from the execute method due to the possibility to specify
     * the argument array directly.
     */
    public void executeArray()
    {
        List<String> cmdList = ArgumentHandler.require(TonkaBeanOption.EXEC_ARRAY);
        executeCommand(cmdList);
    }

    /**
     * The executeCommand function is intended to be called from the execute or executeArray functions.
     * It performs the actual method call to the TonkaBean and displays the results.
     */
    public void executeCommand(List<String> command)
    {
        String cwd = TonkaBeanOption.EXEC_CWD.getValue(".");
        boolean background = TonkaBeanOption.EXEC_BACK.getBool();
        Map<String,String> env = Utils.parseEnvironmentString(TonkaBeanOption.EXEC_ENV.<String>getValue(""));

        if( TonkaBeanOption.EXEC_RAW.getBool() )
            Logger.disableStdout();

        Logger.printMixedYellow("Invoking the", "executeCommand", "method with argument: ");
        Logger.printlnPlainBlue(String.join(" ", command));

        try
        {
            byte[] result = tonkaBean.executeCommand(command.toArray(new String[0]), cwd, env, background);

            if (background)
                return;

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
            ExceptionHandler.handleExecException(e, command);
        }

        catch( IOException e )
        {
            ExceptionHandler.handleFileWrite(e, TonkaBeanOption.EXEC_FILE.<String>getValue(), true);
        }
    }

    /**
     * Dispatcher for the upload action. Reads a file from the local file system and uploads it to the remote
     * MBeanServer.
     */
    public void upload()
    {
        String uploadDest = TonkaBeanOption.UPLOAD_DEST.getValue(null);
        File uploadFile = new File(ArgumentHandler.<String>require(TonkaBeanOption.UPLOAD_SOURCE));

        String uploadSrc = uploadFile.toPath().normalize().toAbsolutePath().toString();

        if (uploadDest == null)
            uploadDest = ".";

        Logger.printMixedYellow("Uploading local file", uploadSrc, "to path ");
        Logger.printlnPlainMixedBlueFirst(uploadDest, "on the MBeanSerer.");

        try
        {
            byte[] content = Utils.readFile(uploadFile);
            String finalPath = tonkaBean.uploadFile(uploadDest, uploadFile.getName(), content);
            Logger.printlnMixedYellowFirst(content.length + " bytes", "were written to", finalPath);
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
        String downloadDest = TonkaBeanOption.DOWNLOAD_DEST.<String>getValue(null);
        File downloadSrc = new File(ArgumentHandler.<String>require(TonkaBeanOption.DOWNLOAD_SOURCE));

        if (downloadDest == null)
            downloadDest = downloadSrc.getName();

        File localFile = new File(downloadDest);

        if(localFile.isDirectory())
            localFile = Paths.get(downloadDest, downloadSrc.getName()).normalize().toFile();

        Logger.printMixedYellow("Saving remote file", downloadSrc.getPath(), "to local path ");
        Logger.printlnPlainBlue(localFile.getAbsolutePath());

        try
        {
            byte[] content = tonkaBean.downloadFile(downloadSrc.getPath());
            FileOutputStream stream = new FileOutputStream(localFile);

            stream.write(content);
            stream.close();

            Logger.printlnMixedYellowFirst(content.length + " bytes", "were written to", localFile.getAbsolutePath());
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
        String targetHost = BeanshooterOption.TARGET_HOST.getValue();

        String[] shellVars = shellInit();
        String username = shellVars[0];
        String hostname = shellVars[1];
        String separator = shellVars[2];

        List<String> shell = getShell(separator);

        if (hostname == null)
            hostname = targetHost;

        do {
            Logger.printPlainYellow(String.format("[%s@%s", username, hostname));
            Logger.printPlainMixedBlue("", cwd);
            Logger.printPlainYellow("]");
            Logger.printPlain("$ ");
            command = console.readLine();

        } while (handleShellCommand(command, shell));
    }

    /**
     * Handle the user specified shell command. This function parses the command and decides what to do
     * with it based on the first specified command item.
     *
     * @param command user specified command within the beanshooter shell
     * @return true if the shell should be kept open, false otherwise
     */
    private boolean handleShellCommand(String command, List<String> shellCmd)
    {
        if( command == null )
            return false;

        String[] commandArray = command.trim().split(" ", 2);
        List<String> shell = new ArrayList<String>(shellCmd);

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
            case "!back":
                if(commandArray.length > 1)
                    shellCommand(commandArray[1], shell, env, true);
                break;

            case "!download":
            case "!get":
                if(commandArray.length > 1)
                    shellDownload(commandArray[1]);
                break;

            case "!upload":
            case "!put":
                if(commandArray.length > 1)
                    shellUpload(commandArray[1]);
                break;

            case "!environ":
            case "!env":
                env.putAll(Utils.parseEnvironmentString(command));
                break;

            case "!help":
            case "!h":
                shellHelp();
                break;

            default:
                shellCommand(command, shell, env, false);
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
        try
        {
            cwd = tonkaBean.toServerDir(cwd, change);
        }

        catch (MBeanException | RuntimeMBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IOException || t instanceof InvalidPathException)
                System.out.println(e.getMessage());

            else {
                Logger.printlnMixedYellow("Caught unexpected", t.getClass().getName(), "while changing directory.");
                ExceptionHandler.stackTrace(e);
            }
        }
    }

    /**
     * Execute the specified shell command and write the output to stdout.
     *
     * @param commandArray command array to execute
     * @param cwd current working directory to operate in
     * @param env environment variables to use for the call
     */
    private void shellCommand(String command, List<String> shell, Map<String,String> env, boolean background)
    {
        shell.add(command);
        String[] commandArray = shell.toArray(new String[0]);

        try
        {
            byte[] result = tonkaBean.executeCommand(commandArray, cwd, env, background);

            if (background)
            {
                Logger.printlnBlue("Command is executed in the background.");
                return;
            }

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
    private void shellUpload(String argument)
    {
        String[] arguments = Utils.splitSpaces(argument, 1);

        File source = new File(Utils.expandPath(arguments[0]));
        File destination = new File(".");

        if (arguments.length > 1)
            destination = new File(arguments[1]);

        if (!destination.isAbsolute())
            destination = Paths.get(cwd, destination.getPath()).toAbsolutePath().normalize().toFile();

        if (!source.isAbsolute())
            source = Paths.get(".", source.getPath()).toAbsolutePath().normalize().toFile();

        try
        {
            byte[] content = Utils.readFile(source);
            String finalPath = tonkaBean.uploadFile(destination.getPath(), source.getName(), content);
            Logger.printlnPlainMixedBlueFirst(content.length + " bytes", "were written to", finalPath);
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
    private void shellDownload(String argument)
    {
        String[] arguments = Utils.splitSpaces(argument, 1);

        File source = new File(arguments[0]);
        File destination = new File(source.getName());

        if (arguments.length > 1)
            destination = new File(Utils.expandPath(arguments[1]));

        if (!source.isAbsolute())
            source = Paths.get(cwd, source.getPath()).toAbsolutePath().normalize().toFile();

        if (!destination.isAbsolute())
            destination = Paths.get(".", destination.getPath()).toAbsolutePath().normalize().toFile();

        if (destination.isDirectory())
            destination = Paths.get(destination.toPath().toString(), source.getName()).toFile();

        try
        {
            byte[] content = tonkaBean.downloadFile(source.getPath());
            FileOutputStream stream = new FileOutputStream(destination);

            stream.write(content);
            stream.close();

            Logger.printlnPlainMixedBlueFirst(content.length + " bytes", "were written to", destination.getPath());
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
    private String[] shellInit()
    {
        try
        {
            return tonkaBean.shellInit();
        }

        catch( MBeanException e )
        {
            ExceptionHandler.unexpectedException(e, "initializing", "shell", true);
        }

        return null;
    }

    /**
     * Helper function to determine the current working directory on shell startup.
     */
    private void initCwd()
    {
        try {
             cwd = tonkaBean.toServerDir(cwd, ".");

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
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !help|!h", 30), "print this help menu");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !environ|!env <key>=<value>", 30), "set new environment variables in key=value format");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !upload|!put <src> <dst>", 30), "upload a file to the remote MBeanServer");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !download|!get <src> <dst>", 30), "download a file from the remote MBeanServer");
        Logger.printlnPlainMixedBlueFirst(Logger.padRight("  !background|!back <cmd>", 30), "executes the specified command in the background");
    }

    private List<String> getShell(String separator)
    {
        String shellCmd = TonkaBeanOption.SHELL_CMD.getValue(null);

        if (shellCmd != null)
            return Arrays.asList(shellCmd.trim().split(" "));

        List<String> shell = new ArrayList<String>();

        if (separator.equals("/"))
        {
            shell.add("sh");
            shell.add("-c");
        }

        else if (separator.equals("\\"))
        {
            shell.add("cmd.exe");
            shell.add("/C");
        }

        else
            ExceptionHandler.internalError("Dispatcher.getShell", "Unhandeled path separator: " + separator);

        return shell;
    }
}
