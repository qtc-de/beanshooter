package de.qtc.beanshooter.mbean.flightrecorder;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.management.MBeanException;
import javax.management.RuntimeMBeanException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.mbean.MBeanInvocationHandler;

/**
 * Dispatcher class for FlightRecorder MXBean operations. Implements operations that are supported
 * by the FlightRecorderMXBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private final FlightRecorderMXBean recorder;

    /**
     * Creates the dispatcher that operates on the FlightRecorderMXBean.
     */
    public Dispatcher()
    {
        super(MBean.FLIGHT_RECORDER);

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        recorder = (FlightRecorderMXBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                  new Class<?>[] { FlightRecorderMXBean.class },
                                                  invo);
    }

    /**
     * Requests the FlightRecorderMXBean to start a new recording and outputs the recording ID to stdout.
     */
    public void newRecording()
    {
        Logger.printlnBlue("Requesting new recording on the MBeanServer.");

        try
        {
            long recordingID = recorder.newRecording();
            Logger.printlnMixedYellow("New recording created successfully with ID:", String.valueOf(recordingID));
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "creation of", "new recording", true);
        }
    }

    /**
     * Starts the recording wit the user specified ID.
     */
    public void startRecording()
    {
        long recordingID = Long.valueOf(ArgumentHandler.<Integer>require(FlightRecorderOption.RECORDING_ID));

        try
        {
            recorder.startRecording(recordingID);
            Logger.printlnMixedYellow("Recording with ID", String.valueOf(recordingID), "started successfully.");
        }

        catch (RuntimeMBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IllegalArgumentException && t.getMessage().contains("No recording available with id"))
                Logger.eprintlnMixedYellow("A recording with ID", String.valueOf(recordingID), "does not exist.");

            else if ( t instanceof IllegalStateException && t.getMessage().contains("Recording can only be started once"))
                Logger.eprintlnMixedYellow("The recording with ID", String.valueOf(recordingID), "was already started.");

            else
                ExceptionHandler.unexpectedException(e, "starting", "recording", true);
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "starting", "recording", true);
        }
    }

    /**
     * Stop the recording with the user specified ID.
     */
    public void stopRecording()
    {
        long recordingID = Long.valueOf(ArgumentHandler.<Integer>require(FlightRecorderOption.RECORDING_ID));

        try
        {
            recorder.stopRecording(recordingID);
            Logger.printlnMixedYellow("Recording with ID", String.valueOf(recordingID), "stopped successfully.");
        }

        catch (RuntimeMBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IllegalArgumentException && t.getMessage().contains("No recording available with id"))
                Logger.eprintlnMixedYellow("A recording with ID", String.valueOf(recordingID), "does not exist.");

            else if ( t instanceof IllegalStateException && t.getMessage().contains("Recording must be started before it can be stopped"))
                Logger.eprintlnMixedYellow("The recording with ID", String.valueOf(recordingID), "was not started yet.");

            else if ( t instanceof IllegalStateException && t.getMessage().contains("Can't stop an already stopped recording"))
                Logger.eprintlnMixedYellow("The recording with ID", String.valueOf(recordingID), "was already stopped.");

            else
                ExceptionHandler.unexpectedException(e, "stopping", "recording", true);
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "stopping", "recording", true);
        }
    }

    /**
     * Saves the content of the user specified recording ID to a file on the local system.
     */
    public void saveRecording()
    {
        long recordingID = Long.valueOf(ArgumentHandler.<Integer>require(FlightRecorderOption.RECORDING_ID));
        Path filename = Paths.get(ArgumentHandler.<String>require(FlightRecorderOption.DUMP_FILE));
        String filenameStr = filename.normalize().toAbsolutePath().toString();

        Logger.printlnMixedYellow("Saving recording with ID:", String.valueOf(recordingID));

        try
        {
            long streamID = recorder.openStream(recordingID, null);
            byte[] content = recorder.readStream(streamID);
            recorder.closeStream(streamID);

            Logger.printlnMixedYellow("Writing recording data to:", filenameStr);
            Files.write(filename, content);
        }

        catch (RuntimeMBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IllegalArgumentException && t.getMessage().contains("No recording available with id"))
                Logger.eprintlnMixedYellow("A recording with ID", String.valueOf(recordingID), "does not exist.");

            else
                ExceptionHandler.unexpectedException(e, "saving", "recording", true);
        }

        catch (MBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IOException && t.getMessage().contains("Recording must be stopped"))
                Logger.eprintlnMixedYellow("The specified recording", "must be stopped", "before it can be saved.");

            else
                ExceptionHandler.unexpectedException(e, "saving", "recording", true);
        }

        catch (IOException e)
        {
            ExceptionHandler.handleFileWrite(e, filenameStr, true);
        }
    }

    /**
     * Dumps the recording with the user specified recording ID to a file on the JMX server.
     */
    public void dumpRecording()
    {
        long recordingID = Long.valueOf(ArgumentHandler.<Integer>require(FlightRecorderOption.RECORDING_ID));
        String filename = ArgumentHandler.require(FlightRecorderOption.DUMP_FILE);

        try
        {
            recorder.copyTo(recordingID, filename);
            Logger.printMixedYellow("Recording with ID", String.valueOf(recordingID), "was successfully dumped to ");
            Logger.printlnPlainBlue(filename);
        }

        catch (RuntimeMBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IllegalArgumentException && t.getMessage().contains("No recording available with id"))
                Logger.eprintlnMixedYellow("A recording with ID", String.valueOf(recordingID), "does not exist.");

            else
                ExceptionHandler.unexpectedException(e, "dumping", "recording", true);
        }

        catch (MBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IOException)
            {
                if (t.getMessage().contains("has not started"))
                {
                    Logger.eprintlnMixedYellow("Recording with ID", String.valueOf(recordingID), "was not started yet.");
                    Logger.eprintlnMixedBlue("Nothing to dump.", "Start the recording", "first.");
                }

                else {
                    Logger.eprintlnMixedYellow("Dumping recording to file on the JMX server caused an", "IOException.");
                    ExceptionHandler.handleFileWrite(t, filename, true);
                }
            }

            else
                ExceptionHandler.unexpectedException(e, "dumping", "recording", true);
        }
    }
}
