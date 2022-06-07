package de.qtc.beanshooter.mbean.flightrecorder;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.management.MBeanException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.mbean.MBeanInvocationHandler;

/**
 * Dispatcher class for MLet MBean operations. Implements operations that are supported
 * by the MLet MBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private final FlightRecorderMXBean recorder;

    /**
     * Creates the dispatcher that operates on the MLet MBean.
     */
    public Dispatcher()
    {
        super(MBean.FLIGHT_RECORDER);

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        recorder = (FlightRecorderMXBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                  new Class<?>[] { FlightRecorderMXBean.class },
                                                  invo);
    }

    public void newRecording()
    {
        Logger.printlnBlue("Requesting new recording on the MBeanServer");

        try
        {
            long recordingID = recorder.newRecording();
            Logger.printlnMixedYellow("New recording created successfully with ID:", String.valueOf(recordingID));
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "creation of", "new record", true);
        }
    }

    public void startRecording()
    {
        long recordingID = Long.valueOf(ArgumentHandler.<Integer>require(FlightRecorderOption.RECORDING_ID));

        try
        {
            recorder.startRecording(recordingID);
            Logger.printlnMixedYellow("Recording with ID", String.valueOf(recordingID), "started successfully.");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "starting", "recording", true);
        }
    }

    public void stopRecording()
    {
        long recordingID = Long.valueOf(ArgumentHandler.<Integer>require(FlightRecorderOption.RECORDING_ID));

        try
        {
            recorder.stopRecording(recordingID);
            Logger.printlnMixedYellow("Recording with ID", String.valueOf(recordingID), "stopped successfully.");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "stopping", "recording", true);
        }
    }

    public void readRecording()
    {
        long recordingID = Long.valueOf(ArgumentHandler.<Integer>require(FlightRecorderOption.RECORDING_ID));
        Path filename = Paths.get(ArgumentHandler.<String>require(FlightRecorderOption.DUMP_FILE));
        String filenameStr = filename.normalize().toAbsolutePath().toString();

        Logger.printlnMixedYellow("Reading recording with ID:", String.valueOf(recordingID));

        try
        {
            long streamID = recorder.openStream(recordingID, null);
            byte[] content = recorder.readStream(streamID);
            recorder.closeStream(streamID);

            Logger.printlnMixedYellow("Writing recording data to:", filenameStr);
            Files.write(filename, content);
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "dumping", "recording", true);
        }

        catch (IOException e)
        {
            ExceptionHandler.handleFileWrite(e, filenameStr, true);
        }
    }

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

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "dumping", "recording", true);
        }
    }
}
