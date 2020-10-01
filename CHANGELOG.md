# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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
* Add color suppoer

### Changed

* Changed the paramater layout during execute actions
* Changed the bash completion script to include new options
* Changed the folder structures and class layouts

### Example Server

* Add additional example server running a different tomcat version
* Add cve-2016-3427 vulnerability to the example server
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
