package de.qtc.beanshooter.cli;

import java.util.HashMap;
import java.util.Objects;

import net.sourceforge.argparse4j.inf.ArgumentGroup;
import net.sourceforge.argparse4j.inf.ArgumentParser;

/**
 * The OptionGroup enum contains logical groupings that are applied within the beanshooter
 * help menu. Related Options get assigned to these groups and are grouped within the help.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum OptionGroup
{
    BEAN("MBean options"),
    TARGET("target arguments"),
    CONNECTION("connection arguments"),
    ACTION("action arguments"),
    GENERAL("general arguments"),
    NONE("");

     private final String name;
     private final HashMap<Pair,ArgumentGroup> argumentGroups;

    /**
     * OptionGroups are initialized by the group name that should be displayed within the help menu.
     *
     * @param name ArgumentGroup name to display in the help menu
     */
     OptionGroup(String name)
    {
        this.name = name;
        this.argumentGroups = new HashMap<Pair,ArgumentGroup>();
    }

    /**
     * Helper function that adds the ArgumentGroup to an ArgumentParser. Each beanshooter operation
     * uses a separate subparser. Each subparser contains it's own ArgumentGroup. Therefore, it is required to
     * create each ArgumentGroup for each operation. Furthermore, some operations are overloaded. The deploy
     * operation from the MBeanOperation class is e.g. defined for each available supported MBean. Therefore,
     * ArgumentGroups are actually assigned to an ArgumentParser-Operation Pair.
     *
     * This function first checks whether the ArgumentGroup for the specified ArgumentParser-Operation Pair was
     * already created. If so, it is simply returned. Otherwise, it is created, added to the parser and added
     * to an internally stored HashMap for later use.
     *
     * @param argParser ArgumentParser to add the ArgumentGroup to
     * @param operation beanshooter operation for the current ArgumentGroup
     * @return ArgumentGroup for the specified operation
     */
    public ArgumentGroup addArgumentGroup(ArgumentParser argParser, Operation operation)
    {
        Pair pair = new Pair(argParser, operation);
        ArgumentGroup group = argumentGroups.get(pair);

        if( group == null )
        {
            group = argParser.addArgumentGroup(name);
            argumentGroups.put(pair, group);
        }

        return group;
    }

    /**
     * Helper class to make a combination of one ArgumentParser and one Operation to a hashable
     * item that can be used within a HashMap. This is required, since ArgumentGroups are assigned
     * to ArgumentParser-Operation pairs.
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    class Pair
    {
        private ArgumentParser parser;
        private Operation operation;

        /**
         * Initialize the pair by specifying the corresponding ArgumentParser and Operation values.
         *
         * @param parser ArgumentParser contained in the pair
         * @param operation Operation contained in the pair
         */
        Pair(ArgumentParser parser, Operation operation)
        {
            this.parser = parser;
            this.operation = operation;
        }

        /**
         * Create a hashCode from the compound Pair object.
         */
        public int hashCode()
        {
            return Objects.hash(parser, operation);
        }

        /**
         * Two Pairs are equal when they contain the same ArgumentParser and Operation values.
         */
        public boolean equals(Object obj)
        {
            if( !(obj instanceof Pair) )
                return false;

            Pair other = (Pair)obj;

            if( other.parser == this.parser && other.operation == this.operation )
                return true;

            return false;
        }
    }
}
