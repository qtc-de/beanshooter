package de.qtc.beanshooter.mbean.tomcat;

import de.qtc.beanshooter.io.Logger;

/**
 * The TomcatUser class is a helper class to format tomcat users. When user information is
 * enumerated, it is stored in TomcatUser objects.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class TomcatUser
{
    private final String username;
    private final String password;
    private final String[] groups;
    private final String[] roles;

    /**
     * Create a new TomcatUser using some basic user information.
     *
     * @param username
     * @param password
     * @param groups
     * @param roles
     */
    public TomcatUser(String username, String password, String[] groups, String[] roles)
    {
        this.username = username;
        this.password = password;
        this.groups = groups;
        this.roles = roles;
    }

    /**
     * Print an formatted overview on the user to stdout.
     */
    public void listUser()
    {
        Logger.println(new String(new char[40]).replace("\0", "-"));

        Logger.printlnBlue("Username:");
        Logger.increaseIndent();
        Logger.printlnYellow(username);
        Logger.decreaseIndent();

        Logger.printlnBlue("Password:");
        Logger.increaseIndent();
        Logger.printlnYellow(password);
        Logger.decreaseIndent();

        if( roles.length > 0 )
        {
            Logger.printlnBlue("Roles:");
            Logger.increaseIndent();

            for(String role : roles)
            {
                Logger.printlnYellow(role);
            }

            Logger.decreaseIndent();
        }

        if( groups.length > 0 )
        {
            Logger.printlnBlue("Groups:");
            Logger.increaseIndent();

            for(String group : groups)
            {
                Logger.printlnYellow(group);
            }

            Logger.decreaseIndent();
        }
    }
}