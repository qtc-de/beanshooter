package de.qtc.beanshooter.plugin.providers;

import de.qtc.beanshooter.cli.Operation;
import de.qtc.beanshooter.plugin.IPayloadProvider;
import de.qtc.beanshooter.utils.YsoIntegration;

public class YsoSerialProvider implements IPayloadProvider {

	 public Object getPayloadObject(Operation action, String name, String args)
	 {
		 return YsoIntegration.getPayloadObject(name, args);
	 }
}