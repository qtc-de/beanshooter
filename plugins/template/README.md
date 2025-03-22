### Plugin Template

----

This folder contains a template for developing *beanshooter* plugins.
Simply adjust the [Template Class](src/main/java/eu/tneitzel/beanshooter/plugin/Template.java)
to your requirements and compile the template using *maven*. If you change the
template class' classname, make sure to also reflect this change within the `BeanshooterPluginClass`
property within [pom.xml](https://github.com/qtc-de/beanshooter/blob/master/plugin/template/pom.xml#L39).

The template contains placeholder implementations for all available plugin interfaces.
Make sure to remove all interfaces and the associated methods that are not actually used
by your plugin.
