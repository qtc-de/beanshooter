package de.qtc.beanshooter.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.IOUtils;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.utils.Utils;

/**
 * The WordlistHandler is responsible for reading in password and username wordlists.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class WordlistHandler
{
    private final static String defaultWordlist = "/default-credentials.txt";

    /**
     * Function that is called to obtain the candidate credentials from the user specified command line
     * arguments. This function reads either the user specified password/username, password-file/username-file
     * or the default wordlist contained in beanshooter and returns the corresponding credentials.
     *
     * @return Map containing username -> password-set combinations
     */
    public static Map<String,Set<String>> getCredentialMap()
    {
        String[] usernames = null;
        String[] passwords = null;

        if (BeanshooterOption.BRUTE_USER.notNull())
            usernames = new String[] { BeanshooterOption.BRUTE_USER.getValue() };

        else if (BeanshooterOption.BRUTE_USER_FILE.notNull())
            usernames = readWordlist(BeanshooterOption.BRUTE_USER_FILE.getValue(), "user");

        if (BeanshooterOption.BRUTE_PASSWORD.notNull())
            passwords = new String[] { BeanshooterOption.BRUTE_PASSWORD.getValue() };

        else if (BeanshooterOption.BRUTE_PW_FILE.notNull())
            passwords = readWordlist(BeanshooterOption.BRUTE_PW_FILE.getValue(), "password");

        if (usernames == null && passwords != null)
        {
            Logger.eprintlnMixedYellowFirst("No username(s)", "specified for the brute action.");
            Utils.exit();
        }

        else if (usernames != null && passwords == null)
        {
            Logger.eprintlnMixedYellowFirst("No password(s)", "specified for the brute action.");
            Utils.exit();
        }

        else if (usernames != null && passwords != null)
            return makeMap(usernames, passwords);

        return readCredpairList();
    }

    /**
     * Read the specified wordlist file, split in on newlines and return the result as an array
     * of String.
     *
     * @param filename path to the wordlist file to read
     * @param type type name of the wordlist file (user or password). Only used for logging
     * @return contained wordlist items as array of String
     */
    private static String[] readWordlist(String filename, String type)
    {
        Logger.printlnMixedBlue(String.format("Reading %s wordlist:", type), filename);

        try
        {
            return new String(Utils.readFile(filename)).split("\n");
        }
        catch (IOException e)
        {
            ExceptionHandler.handleFileRead(e, filename, true);
        }

        return new String[] {};
    }

    /**
     * Read the default credential list. In contrast to user defined list, this list is in
     * username:password format. We may use this function in future to also allow user defined
     * wordlists in username:password format.
     *
     * @return credential map obtained from the default wordlist
     */
    private static Map<String,Set<String>> readCredpairList()
    {
        Logger.printlnBlue("Reading credentials from internal wordlist.");
        Map<String,Set<String>> bruteMap = new HashMap<String,Set<String>>();

        try {
            InputStream stream = WordlistHandler.class.getResourceAsStream(defaultWordlist);
            String content = new String(IOUtils.toByteArray(stream));
            stream.close();

            for(String line : content.split("\n"))
            {
                String[] split = line.split(":");
                if(split.length != 2)
                    throw new IOException("Invalid credential file!");

                if(bruteMap.containsKey(split[0]))
                    bruteMap.get(split[0]).add(split[1]);

                else
                {
                    Set<String> passwords = new HashSet<String>();
                    passwords.add(split[1]);
                    bruteMap.put(split[0], passwords);
                }
            }
        }

        catch (IOException e)
        {
            ExceptionHandler.unexpectedException(e, "reading", "internal wordlist", true);
        }

        return bruteMap;
    }

    /**
     * Helper function to convert an array of usernames and an array of passwords into
     * the required credential map format.
     *
     * @param usernames array of usernames for the map
     * @param passwords array of passwords for the map
     * @return credential map
     */
    private static Map<String,Set<String>> makeMap(String[] usernames, String[] passwords)
    {
        Map<String,Set<String>> bruteMap = new HashMap<String,Set<String>>();

        for(String username : usernames)
            bruteMap.put(username, new HashSet<String>(Arrays.asList(passwords)));

        return bruteMap;
    }
}
