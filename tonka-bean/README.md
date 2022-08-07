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
    public String version();
    public String[] shellInit();
    public String toServerDir(String current, String change) throws IOException, InvalidPathException;
    public byte[] downloadFile(String filename) throws IOException;
    public String uploadFile(String destination, String filename, byte[] content) throws IOException;
    public byte[] executeCommand(String[] cmd, String cwd, Map<String,String> env, boolean background) throws IOException, InterruptedException;
}
```
