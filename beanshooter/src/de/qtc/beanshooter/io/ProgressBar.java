package de.qtc.beanshooter.io;

import de.qtc.beanshooter.operation.BeanshooterOption;

/**
 * Simple progress bar.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ProgressBar {

    protected int done;
    protected int work;
    protected final int length;
    protected final String formatString;

    /**
     * Initialize the progress bar with the amount of work and the desired length.
     *
     * @param work Amount of work that needs to be done
     * @param length Length of the actual progress bar (# - part)
     */
    public ProgressBar(int work, int length)
    {
        this.work = work;
        this.length = length;
        this.done = 0;

        int digits = String.valueOf(work).length();
        this.formatString = "[%" + String.valueOf(digits) + "d / %d] [%s] %3d%%\r";
    }

    /**
     * Should be called after the task the ProgressBar was used for is done. Prints a newline
     * if a bar was used to separate it from the following output.
     */
    public void done()
    {
        if(!BeanshooterOption.NO_PROGRESS.getBool())
            Logger.lineBreak();
    }

    /**
     * This function allows to add work to the bar. Currently not used.
     */
    public synchronized void addWork()
    {
        if(BeanshooterOption.NO_PROGRESS.getBool())
            return;

        this.work += 1;
    }

    /**
     * Is called for each task that is done. Increases the number of done tasks and
     * updates the progress bar.
     */
    public synchronized void taskDone()
    {
        if(BeanshooterOption.NO_PROGRESS.getBool())
            return;

        this.done += 1;
        printBar();
    }

    /**
     * Prints the current progress bar to stdout.
     */
    private void printBar()
    {
        float progress = (float)done / work;

        int percentage = (int) Math.round(progress * 100);
        int barLength = (int) Math.round(progress * length);

        String progressBar = new String(new char[barLength]).replace("\0", "#");
        progressBar = progressBar + new String(new char[length - barLength]).replace("\0", " ");
        progressBar = String.format(formatString, done, work, progressBar, percentage);

        Logger.print(progressBar);
    }
}
