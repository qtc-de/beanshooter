package de.qtc.tonkabean;

public interface TonkaBeanMBean {
    public String executeCommand(String cmd);
    public String executeCommandBackground(String cmd);
    public String ping();
}
