### beanshooter

----

*beanshooter* is a *JMX* enumeration and attacking tool, which helps to identify common vulnerabilities on *JMX* endpoints.

![](https://github.com/qtc-de/beanshooter/workflows/master%20maven%20CI/badge.svg?branch=master)
![](https://github.com/qtc-de/beanshooter/workflows/develop%20maven%20CI/badge.svg?branch=develop)
[![](https://img.shields.io/badge/version-3.0.0-blue)](https://github.com/qtc-de/beanshooter/releases)
[![](https://img.shields.io/badge/build%20system-maven-blue)](https://maven.apache.org/)
![](https://img.shields.io/badge/java-8%2b-blue)
[![](https://img.shields.io/badge/license-GPL%20v3.0-blue)](https://github.com/qtc-de/beanshooter/blob/master/LICENSE)


### Table of Contents

----

- [Installation](#installation)
- [Supported Operations](#supported-operations)
  + [Basic Operations](#basic-operations)
    - [brute](#brute)
    - [invoke](#invoke)
    - [deploy](#deploy)
    - [enum](#enum)
    - [list](#list)
    - [serial](#serial)
    - [undeploy](#undeploy)
  + [MBean Operations](#mbean-operations)
    - [generic](#generic)
      + [info](#generic-info)
      + [export](#generic-export)
      + [status](#generic-status)
      + [deploy](#generic-deploy)
      + [undeploy](#generic-undeploy)
    - [tonka](#tonka)
      + [exec](#tonka-exec)
      + [background](#tonka-background)
      + [shell](#tonka-shell)
      + [upload](#tonka-upload)
      + [download](#tonka-download)
    - [mlet](#mlet)
      + [load](#mlet-load)
    - [tomcat](#tomcat)
      + [list](#tomcat-list)

- [Example Server](#example-server)


### Installation

-----

*beanshooter* is a *maven* project and installation should be straight forward. With [maven](https://maven.apache.org/) 
installed, just execute the following commands to create an executable ``.jar`` file:

```console
$ git clone https://github.com/qtc-de/beanshooter
$ cd beanshooter
$ mvn package
```

You can also use prebuild packages that are created for [each release](https://github.com/qtc-de/beanshooter/releases).
Prebuild packages for the development branch are created automatically and can be found on the *GitHub*
[actions page](https://github.com/qtc-de/beanshooter/actions).

*beanshooter* does not include *ysoserial* as a dependency. To enable *ysoserial* support, you need either specify the path
to your ``ysoserial.jar`` file as additional argument (e.g. ``--yso /opt/ysoserial.jar``) or you change the
default path within the [beanshooter configuration file](./beanshooter/config.properties) before building the project.

*beanshooter* supports autocompletion for *bash*. To take advantage of autocompletion, you need to have the
[completion-helpers](https://github.com/qtc-de/completion-helpers) project installed. If setup correctly, just
copying the [completion script](/resources/bash_completion.d/beanshooter) to your ``~/.bash_completion.d`` folder enables
autocompletion.

```console
$ cp resources/bash_completion.d/beanshooter ~/bash_completion.d/
```


### Supported Operations

-----

The different *beanshooter* operations can be divided into two groups: *basic operations* and *MBean operations*. Whereas
*baisc operations* are used to perform general operations on a *JMX* endpoint, *MBean operations* target a specific *MBean*
to interact with. For more details, check the usage examples in the following sections.

```console
[qtc@devbox ~]$ beanshooter -h
usage: beanshooter [-h]   ...

beanshooter v3.0.0 - a JMX enumeration and attacking tool

positional arguments:
                          
 Basic Operations
    brute                bruteforce JMX credentials
    invoke               invoke the specified method on the specified MBean
    deploy               deploys the specified MBean on the JMX server
    enum                 enumerate the JMX service for common vulnerabilities
    list                 list available MBEans on the remote MBean server
    serial               perform a deserialization attack
    undeploy             undeploys the specified MBEAN from the JMX server

 MBean Operations
    tonka                general purpose bean for executing commands and uploading or download files
    mlet                 default JMX bean that can be used to load additional beans dynamically
    tomcat               tomcat MemoryUserDatabaseMBean used for user management

named arguments:
  -h, --help             show this help message and exit
```


### Example Server

---

Most of the examples presented above are based on the [jmx-example-server](https://github.com/qtc-de/beanshooter/pkgs/container/beanshooter%2Fjmx-example-server)
and the [tomcat-example-server](https://github.com/qtc-de/beanshooter/pkgs/container/beanshooter%2Ftomcat-example-server).
These servers are contained within this repository in the [docker](/docker) folder and can be used to practice *JMX* enumeration.
You can either build the corresponding containers yourself or load them directly from the *GitHub Container Registry*.

Copyright 2022, Tobias Neitzel and the *beanshooter* contributors.
