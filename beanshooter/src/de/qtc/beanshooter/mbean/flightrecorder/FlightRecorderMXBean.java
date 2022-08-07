package de.qtc.beanshooter.mbean.flightrecorder;

import javax.management.MBeanException;
import javax.management.openmbean.TabularData;

/**
 * Interface of available FlightRecorder operations. Since we only implement a subset of the
 * actually available operations exposed by this MBean, we use a custom interface
 * instead of the original one.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface FlightRecorderMXBean
{
    public long newRecording() throws MBeanException;
    public long openStream(long recordingId, TabularData streamOptions) throws MBeanException;
    public void closeStream(long streamId) throws MBeanException;
    public byte[] readStream(long streamId) throws MBeanException;
    public void startRecording(long recordingId) throws MBeanException;
    public void stopRecording(long recordingId) throws MBeanException;
    public void copyTo(long recordingId, String outputFile) throws MBeanException;
}
