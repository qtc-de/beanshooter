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
     * Return the username of the TomcatUser object.
     *
     * @return the associated username
     */
    public String getUsername()
    {
        return username;
    }

    /**
     * Return the password of the TomcatUser object.
     *
     * @return the associated password
     */
    public String getPassword()
    {
        return password;
    }

    /**
     * Print an formatted overview on the user to stdout.
     */
    public void listUser()
    {
        Logger.println(new String(new char[40]).replace("\0", "-"));

        Logger.printlnMixedBlueYellow("Username:", "", username);
        Logger.printlnMixedBlueYellow("Password:", "", password);

        if( roles.length > 0 )
        {
            Logger.printlnBlue("Roles:");
            Logger.increaseIndent();

            for(String role : roles)
            {
                Logger.printlnMixedYellow("  ", role);
            }

            Logger.decreaseIndent();
        }

        if( groups.length > 0 )
        {
            Logger.printlnBlue("Groups:");
            Logger.increaseIndent();

            for(String group : groups)
            {
                Logger.printlnMixedYellow("  ", group);
            }

            Logger.decreaseIndent();
        }
    }
}
