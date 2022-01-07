package de.qtc.beanshooter.cli;

import java.util.HashMap;

import de.qtc.beanshooter.operation.Operation;
import net.sourceforge.argparse4j.inf.ArgumentGroup;
import net.sourceforge.argparse4j.inf.ArgumentParser;

/**
 * The OptionGroup enum contains logical groupings that are applied within the beanshooter
 * help menu. Related Options get assigned to these groups and are grouped within the help.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum OptionGroup {

    BEAN("MBean options"),
    TARGET("target arguments"),
    CONNECTION("connection arguments"),
    ACTION("action arguments"),
    GENERAL("general arguments"),
    NONE("");

     private final String name;
     private final HashMap<Operation,ArgumentGroup> argumentGroups;

    /**
     * OptionGroups are initialized by the group name that should be displayed within the help menu.
     *
     * @param name ArgumentGroup name to display in the help menu
     */
     OptionGroup(String name)
    {
        this.name = name;
        this.argumentGroups = new HashMap<Operation,ArgumentGroup>();
    }

    /**
     * Helper function that adds the ArgumentGroup to an ArgumentParser. Each beanshooter operation
     * uses a separate subparser. Each subparser contains it's own ArgumentGroup. Therefore, it is required to
     * create each ArgumentGroup for each operation.
     *
     * This function first checks whether the ArgumentGroup for the specified operation was already created.
     * If so, it is simply returned. Otherwise, it is created, added to the parser and added to an internally
     * stored HashMap for later use.
     *
     * @param argParser ArgumentParser to add the ArgumentGroup to
     * @param operation beanshooter operation for the current ArgumentGroup
     * @return ArgumentGroup for the specified operation
     */
    public ArgumentGroup addArgumentGroup(ArgumentParser argParser, Operation operation)
    {
        ArgumentGroup group = argumentGroups.get(operation);

        if( group == null ) {
            group = argParser.addArgumentGroup(name);
            argumentGroups.put(operation, group);
        }

        return group;
    }
}
