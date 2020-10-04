### Tonka Bean

----

The *tonka-bean* is a *proof-of-concept* for a malicious *MBean* that can be deployed by *beanshooter*. Once deployed
on the target, it allows command execution and file system access through the *JMX* endpoint.


### Installation

-----

The *tonka-bean* is a *maven* project. This makes the installation a straight forward process.
First of all, make sure you have *maven* installed on your system:

```console
# apt install maven           # Debian
# pacman -s maven             # Arch
```

With *maven* available, run ``mvn package`` inside of the projects folder.

```console
[qtc@kali tonka-bean]$ mvn package
[INFO] Scanning for projects...
[INFO] 
[INFO] --------------------< de.qtc.TonkaBean:tonka-bean >---------------------
[INFO] Building tonka-bean 1.1.0
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] 
[...]
```

After *maven* finished, you should find the compiled *MBean* inside of the ``target`` folder.

```console
[qtc@kali tonka-bean]$ ls -l target/tonka-bean.jar 
-rw-r--r-- 1 qtc qtc 2751 Oct  4 07:42 target/tonka-bean.jar
```


### Usage

----

Instructions on how to deploy the *tonka-bean* on a *JMX* agent are already given in the
*beanshooter* documentation. Once deployed, the following functions are exposed through
the *JMX* endpoint:

```java
public interface TonkaBeanMBean {

    public String ping();

    public void executeCommandBackground(String cmd) throws IOException;
    public String executeCommand(String cmd) throws IOException, InterruptedException ;

    public byte[] downloadFile(String filename) throws IOException;
    public String uploadFile(String destination, byte[] content) throws IOException;
}
```

The following list contains a short explanation to each function:

* ``public String ping()``: This function is just for verification that the *tonka-bean* was deployed
  correctly. On invocation, the function just returns the *String* ``pong!``.

* ``public void executeCommandBackground(String cmd)``: Executes the specified command in the background.
* ``public String executeCommand(String cmd)``: Executes the specified command and returns the corresponding
  standard output and standard error.

* ``public byte[] downloadFile(String filename)``: Attempts to read the file from the specified path and
  returns the result as a *bytearray*.
* ``public String uploadFile(String destination, byte[] content)``: Writes the *bytearray* ``content`` to the
  specified path on the file system of the server.
