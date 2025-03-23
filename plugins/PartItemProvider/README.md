### PartItemProvider

----

The PartItemProvider plugin implements the IPayloadProvider interface. The plugin is intended to be used
during beanshooters serial action to provide a custom deserialization gadget. The provided gadget is the
PartItem class that is available by default in *GlassFish*.

PartItem is a class present in the web-core module of *GlassFish*. It contains a vulnerable readObject and
finalize method, that can be abused to perform file operations during deserialization. Since the PartItem
class is very simple and only needs to contain one field for a deserialization attack, we define the class
ourselves within this payload provider. The more common scenario would be to import the vulnerable dependencies
(web-core.jar in our case) and to construct the payload as a regular object.
