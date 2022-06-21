package de.qtc.beanshooter.operation;

import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.io.ProgressBar;
import de.qtc.beanshooter.plugin.PluginSystem;
import de.qtc.beanshooter.utils.Utils;

/**
 * The CredentialGuesser is used to perform bruteforce attacks on JMX endpoints.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class CredentialGuesser
{
    private final String host;
    private final int port;

    private final int count;
    private final GuessingProgressBar bar;
    private final Map<String,Set<String>> credentials;

    private ExecutorService pool;

    /**
     * Create a CredentialGuesser by specifying a target and the credential map that should be used.
     *
     * @param host target host
     * @param port target port
     * @param credentials credential map containing username -> password-set combinations
     */
    public CredentialGuesser(String host, int port, Map<String,Set<String>> credentials)
    {
        this.host = host;
        this.port = port;

        this.credentials = credentials;
        this.count = countItems();

        this.bar = new GuessingProgressBar(count, 40);
    }

    /**
     * Start the bruteforce attack. Results are printed to stdout directly.
     */
    public void startGuessing()
    {
        Logger.printlnMixedYellow("Starting bruteforce attack with", String.valueOf(count), "credentials.");
        Logger.lineBreak();
        Logger.increaseIndent();

        EnumHelper enumHelper = new EnumHelper(host, port);
        if( BeanshooterOption.CONN_SASL.isNull() && !enumHelper.requiresLogin() )
        {
            Logger.printlnMixedYellow("The targeted JMX service accepts", "unauthenticated", "connections.");
            Logger.println("No need to bruteforce credentials.");
            return;
        }

        enumHelper.checkLoginFormat();

        int threads = ArgumentHandler.require(BeanshooterOption.BRUTE_THREADS);
        pool = Executors.newFixedThreadPool(threads);

        for(Entry<String,Set<String>> entry : credentials.entrySet())
        {
            for(Set<String> pwSet : Utils.splitSet(entry.getValue(), threads))
            {
                Runnable r = new GuessingWorker(entry.getKey(), pwSet);
                pool.execute(r);
            }
        }

        try
        {
            pool.shutdown();
            pool.awaitTermination(Long.MAX_VALUE, TimeUnit.SECONDS);
        }

        catch (InterruptedException e)
        {
             Logger.eprintln("Interrupted!");
        }

        finally
        {
            Logger.decreaseIndent();
            bar.done();

            Logger.lineBreak();
            Logger.println("done.");
        }
    }

    /**
     * Helper function to count the actual amount of guesses to be done.
     *
     * @return number of credentials that need to be guessed.
     */
    private int countItems()
    {
        int count = 0;

        for(Entry<String,Set<String>> entry : credentials.entrySet())
        {
            count += entry.getValue().size();
        }

        return count;
    }

    /**
     * Bruteforce attacks are multithreaded. The GuessingWorker class implements a worker that can
     * run inside a thread.
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    private class GuessingWorker implements Runnable
    {
        private final String username;
        private final Set<String> passwords;

        /**
         * GuessingWorkers use a fixed username and a set of passwords that should be guessed. This is not
         * always ideal (e.g. if a fixed password was specified and only usernames should be guessed). We
         * may improve the implementation in future.
         *
         * @param username fixed username to use for guessing
         * @param passwords set of passwords that should be guessed
         */
        public GuessingWorker(String username, Set<String> passwords)
        {
            this.username = username;
            this.passwords = passwords;
        }

        /**
         * Perform the actual bruteforcing.
         */
        public void run()
        {
            for(String password : passwords)
            {
                Map<String,Object> env = PluginSystem.getEnv(username, password);

                try
                {
                    PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);
                    bar.printSuccess(username, password);

                    if( BeanshooterOption.BRUTE_FIRST.getBool() )
                        pool.shutdownNow();
                }

                catch (AuthenticationException e) {}

                finally
                {
                    bar.taskDone();
                }
            }
        }
    }

    /**
     * In case of a valid credential hit, we need to clear the progress bar and print the hit result.
     * Using the Beanshooter Logger class, two prints are required, which may causes problems when other
     * threads want to print at the same time. To make the print atomic, we use a synchronized function
     * within the ProgressBar. However, ProgressBar is a general purpose class and may not only be used
     * for bruteforcing in future. Therefore, we extend it to add the required synchronized function.
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    private class GuessingProgressBar extends ProgressBar
    {
        /**
         * Initialize the bar by using it's parent constructor.
         *
         * @param work amount of work to be done
         * @param length length of the '#'-part of the bar
         */
        public GuessingProgressBar(int work, int length)
        {
            super(work, length);
        }

        /**
         * Clear the bar and print a success message.
         *
         * @param username identified username
         * @param password identified password
         */
        public synchronized void printSuccess(String username, String password)
        {
            Logger.print(new String(new char[length + 20]).replace("\0", " ") + "\r");
            Logger.printlnMixedYellow("Found valid credentials:", String.format("%s:%s", username, password));
        }
    }
}
