## tonka-bean

The tonka-bean is just some malicious Java code that follows the *MBean Specifications*. Once it is deployed
on a *JMX Agent*, it can be used to execute arbitrary operating system commands on the targeted application server.

### Installation

-----

The *tonka-bean* is a *maven* project. This makes the installation a straight forward process and no manual installation of libraries
should be required. First of all, make sure that you have *maven* installed on your system:

```bash
# apt install maven      # Debian
# pacman -s maven             # Arch
```

Then, clone the *tonka-bean* project in a location of your choice and run ``mvn package`` inside of the projects folder.

```bash
[qtc@kali tonka-bean]$ mvn package
[INFO] Scanning for projects...
[INFO] 
[INFO] --------------------< de.qtc.TonkaBean:tonka-bean >---------------------
[INFO] Building tonka-bean 1.0.0
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] 
[...]
```

After *maven* has finished, you should find the compiled *MBean* inside of the ``target`` folder.
