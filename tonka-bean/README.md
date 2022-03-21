### Tonka Bean

----

The *tonka bean* is an example for a malicious *MBean* that can be deployed on a *JMX* server.
It allows to execute arbitrary operating system commands and provides access to the file system
of the *JMX* server.

The *tonka bean* is intended to be deployed and consumed by *beanshooters* `tonka` operation. 
When building *beanshooter*, the *tonka bean* is automatically build too and included into the
*beanshooter* jar file. Building the *tonka bean* manually or using a pre compiled version of it
is therefore not necessary.

The *tonka bean* implements the following interface:

```java
public interface TonkaBeanMBean
{
    public String ping();
    public String username();
    public File toServerDir(File cwd) throws IOException;

    public byte[] executeCommand(String[] cmd, File cwd, Map<String,String> env) throws IOException, InterruptedException ;
    public void executeCommandBackground(String[] cmd, File cwd, Map<String,String> env) throws IOException ;

    public byte[] downloadFile(String filename) throws IOException;
    public String uploadFile(String destination, byte[] content) throws IOException;
}
```
