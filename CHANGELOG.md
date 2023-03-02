# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [4.0.0] - Mar XX, 2023

### Added

* Add *Jolokia* support

### Changed

* Make the *TonkaBean* *OpenType* compatible


## [3.1.1] - Jan 19, 2023

### Changed

* Small bugfix in JarHandler that occured when using a file system jar during deployment


## [3.1.0] - Jan 19, 2023

### Added

* Display bound names during enum action
* Display JMX endpoint address during enum action
* Add support for Glassfish and Correto
* Add `--no-canary` option to prevent usage of deserialization canaries
* Add [example plugin](/plugins)

### Changed

* Switch from `iinsecure.dev` to `iinsecure.example` for docker containers
* Switch from *jre11* to *jre17* for tomcat container
* Modify Jar Manifest to include *Add-Opens* (Java16+ support)
* Catch exceptions caused by outdated TLS servers 


## [3.0.0] - Aug 07, 2022

### Added

* Add operations for the `FlightRecorderMXBean`
* Add operations for the `DiagnosticCommandMBean`
* Add operations for the `HotSpotDiagnosticMXBean`
* Add the `attr` action for obtaining and modifying attributes
* Add the `info` action for enumerating method and attributes
* Add the `dump` action for the `MemoryUserDatabaseMBean`
* Add the `write` action for the `MemoryUserDatabaseMBean`

### Changed

* The `invoke` action does no longer allow accessing attributes by using methods starting
  with `get`. Instead, the `attr` action should now be used for attribute access.
* The old *MBean* `info` operations was renamed to `stats`. The `info` action now performs
  the general `info` operation for the specified *MBean*.
* *MBeans* with default support by *beanshooter* are now displayed together with the
  corresponding action name when listing *MBeans*.
* Refactored the completion script.
* Several bugfixes.


## [3.0.0-rc.2] - Jun 07, 2022

### Added

* Added documentation for the docker containers
* Added `execarray` action for the tonka bean
* Added [tricot](https://github.com/qtc-de/tricot) based tests for all actions

### Changed

* Improve the argument handling of the `invoke` action
* Improve the `shell` action (Windows compatibility)
* Replace `execbackground` action with the option `--background`
* Several bug fixes


## [3.0.0-rc.1] - March 21, 2022

Global refactoring. Basically all code sections were renewed and several new features
were implemented.

### Added

* Added the `brute` action for bruteforcing JMX credentials
* Added the `invoke` action for calling arbitrary MBean methods
* Added the `enum` action to enumerate common JMX vulnerabilities
* Added the `list` action to enumerate available MBeans
* Added the `serial` action to perform deserialization attacks
* Added support for the *Apache tomcats* `MemoryUserDatabaseMBean`
* Added support for calling the *MLetMBean* manually
* Added support for *Apache Karaf*

### Changed

* The [example servers]() were renewed and provide now more useful
  [usage examples]()
* The [tonka-bean]() is now included into the *beanshooter* jar file
  Building and providing the *tonka-bean* separately is no longer required
* The *tonka-bean* was renewed and contains several new features and improvements
* The exception handling was improved to provide more detailed information
  in case of an error. Using the `--stack-trace` option allows always to
  investigate the full stack trace if required


## [2.0.1] - Oct 2, 2020

### Changed

* Fixed bug when using quotes within the !upload and !download shell wrappers


## [2.0.0] - Oct 1, 2020

### Added

* Add *SSL* support (for registry and remote objects)
* Add automatic redirection feature
* Add shell action
* Add ysoserial action
* Add cve-2016-3427 action
* Add support for authenticated *JMXMP*
* Add support for *SSL* protected *JMXMP*
* Add new options for separate bind-address and bind-port
* Add color support
* Add upload and download functions

### Changed

* Changed the parameter layout during execute actions
* Changed the bash completion script to include new options
* Changed the folder structures and class layouts

### Example Server

* Add additional example server running a different tomcat version
* Add CVE-2016-3427 vulnerability to the example server
* Add deserialization vulnerability to the example server
* Add authenticated *JMXMP* listeners to the example server
* Add *SSL* protection to *RMI* and *JMXMP* listeners
* Add hostname specification to the registry server


## [1.1.0] - Aug 6, 2020

### Added

* Add autocompletion script
* Add CI workflows

### Changed

* Change default path of ``tonka-bean.jar`` (is now ``/opt/jmx-exploiter/tonka-bean/target``)


## [1.0.0] - Nov 26, 2019

Initial release :)
