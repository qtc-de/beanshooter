package org.apache.catalina.fileupload;

import java.io.File;
import java.io.Serializable;

/**
 * Skeleton for the real org.apache.catalina.fileupload.PartItem class, which
 * is sufficient to perform deserialization attacks.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class PartItem implements Serializable
{
    private static final long serialVersionUID = 2237570099615271025L;
    public File dfosFile;

    public PartItem(String path)
    {
        this.dfosFile = new File(path);
    }
}
