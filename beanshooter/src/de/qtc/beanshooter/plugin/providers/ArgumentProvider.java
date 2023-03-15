package de.qtc.beanshooter.plugin.providers;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.IArgumentProvider;
import de.qtc.beanshooter.utils.Utils;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;

/**
 * The ArgumentProvider class is beanshooters default implementation for the IArgumentProvider interface.
 * It uses javassist to parser user specified argument strings and signatures.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ArgumentProvider implements IArgumentProvider
{
    private Method targetMethod = null;

    /**
     * This function performs basically an eval operation on the user specified argumentArray. The argumentArray is
     * joined by the pattern ", " and passed into the following expression: return new Object[] { " + argumentString + "};
     * This expression is evaluated and the resulting Object array is returned by this function.
     *
     * For this to work, the function performs some additional wrapping around primitive types. If the user specified
     * a function signature that contains e.g. an int type, the function wraps the corresponding argument to
     * Integer.valueOf(<arg>). This is done, because with javassist you cannot have expressions like: "new Object[] {1, 2}"
     * as javassist does not support boxing and unboxing.
     *
     * Since the method signature is required for wrapping, it is important that getArgumentTypes is called before
     * this function, since getArgumentTypes stores the method within the targetMethod field of this class.
     */
     public Object[] getArgumentArray(String[] arguments)
     {
         if (arguments.length != targetMethod.getParameterCount())
             ExceptionHandler.argumentCountMismatch(arguments.length, targetMethod.getParameterCount());

         else if( arguments.length == 0 )
             return new Object[] {};

         Object[] result = null;
         ClassPool pool = ClassPool.getDefault();
         String argumentString = wrapArguments(arguments);

         try {
             CtClass evaluator = pool.makeClass("de.qtc.rmg.plugin.providers.DefaultArgumentProvider");
             String evalFunction = "public static Object[] eval() {"
                                 + "        return new Object[] { " + argumentString + " };"
                                 + "}";

             CtMethod me = CtNewMethod.make(evalFunction, evaluator);
             evaluator.addMethod(me);

             Class<?> evalClass = evaluator.toClass();
             Method m = evalClass.getDeclaredMethods()[0];

             result = (Object[]) m.invoke(evalClass, (Object[])null);

         } catch(VerifyError | CannotCompileException e) {
             ExceptionHandler.invalidArgumentException(e, argumentString);

         } catch (Exception e) {
             ExceptionHandler.unexpectedException(e, "argument array", "generation", true);
         }

         return result;
     }

     /**
      * Create an Object from a Java expression.
      *
      * @param str  Java expression. Class names need to be specified full qualified
      * @return Object created from the Java expression
      */
      public Object strToObj(String str)
      {
          Object result = null;
          ClassPool pool = ClassPool.getDefault();

          try {
              CtClass evaluator = pool.makeClass("de.qtc.rmg.plugin.providers.DefaultArgumentProvider");
              String evalFunction = "public static Object eval() {"
                                  + "        return " + str + ";"
                                  + "}";

              CtMethod me = CtNewMethod.make(evalFunction, evaluator);
              evaluator.addMethod(me);

              Class<?> evalClass = evaluator.toClass();
              Method m = evalClass.getDeclaredMethods()[0];

              result = (Object) m.invoke(evalClass, (Object[])null);

          } catch(VerifyError | CannotCompileException e) {
              ExceptionHandler.invalidArgumentException(e, str);

          } catch (Exception e) {
              ExceptionHandler.unexpectedException(e, "argument array", "generation", true);
          }

          return result;
      }

      /**
       * See description below.
       */
      public String[] getArgumentTypes(String signature)
      {
          return getArgumentTypes(signature, false);
      }

     /**
     * MBean calls are dispatched using an array of argument objects and an array of class names of the
     * corresponding argument types. In ordinary MBean clients, this is no problem, as the methods are available
     * within the client and obtaining the argument types of a method can be done automatically
     * (usually by using an InvocationHandler). In beanshooter, however, we invoke methods dynamically
     * without having the signature available. Therefore, we need some other way to obtain the argument
     * type array.
     *
     * This function parses a user specified function signature like e.g. 'example(int 1, long 2)' and
     * returns the list of type names contained within the signature. It is important that this function
     * returns the correct type names. E.g. it is insufficient to just split the inner part of the signature
     * on commas and to return the first word of each split item. This is because certain types like long[] have
     * different associated class names like '[L'.
     *
     * This function uses javassist and dynamic class creation to get the job done. We use javassist to
     * create a dummy method from the user specified method signature and when obtain the correct
     * type names via reflection and getParameterTypes() on the associated method object.
     */
    public String[] getArgumentTypes(String signature, boolean includeName)
    {
        ClassPool pool = ClassPool.getDefault();
        List<String> result = new ArrayList<String>();
        signature = Utils.makeVoid(signature);

        try {
            CtClass evaluator = pool.makeClass("de.qtc.rmg.plugin.providers.DefaultArgumentProvider2" + System.nanoTime());
            String dummyFunction = "public static " + signature + " {}";

            CtMethod me = CtNewMethod.make(dummyFunction, evaluator);
            evaluator.addMethod(me);

            Class<?> evalClass = evaluator.toClass();
            targetMethod = evalClass.getDeclaredMethods()[0];

            if (includeName)
                result.add(targetMethod.getName());

            for(Class<?> type : targetMethod.getParameterTypes())
                result.add(type.getName());

         } catch (VerifyError | CannotCompileException e) {
             ExceptionHandler.invalidSignature(e, signature);

         } catch (Exception e) {
             ExceptionHandler.unexpectedException(e, "argument array", "generation", true);
         }

         return result.toArray(new String[0]);
     }

    /**
     * Returns the targeted method name from the user specified function signature. This function
     * uses the fact that beanshooter calls getArgumentTypes before getMethodName. Therefore, we can use
     * the already created method to obtain the method name.
     */
    public String getMethodName(String signature)
    {
        return targetMethod.getName();
    }

    /**
     * Takes an array of user specified arguments and wraps the primitive types in it. Afterwards,
     * all arguments are joined by ", " to create an argument string. The following argument array
     * 'new String[] { 1, "Hello"}' would be wrapped to 'Integer.valueOf(1), "Hello"'.
     *
     * Object types are generally leaved as they are, except of String. String is wrapped into double
     * quotes. This saves users from specifying String arguments like '"Hello"' on the command line.
     *
     * @param argumentArray user specified argument Array
     * @return argument string that can be sued within javassist
     */
    private String wrapArguments(String[] argumentArray)
    {
        List<String> wrappedArgs = new ArrayList<String>();
        Class<?>[] paramTypes = targetMethod.getParameterTypes();

        for(int ctr = 0; ctr < argumentArray.length; ctr++)
            wrappedArgs.add(wrap(argumentArray[ctr], paramTypes[ctr]));

        return String.join(", ", wrappedArgs);
    }

    /**
     * Wraps the specified argument according to the specified type. All primitive arguments are
     * wrapped into their corresponding wrapper classes (e.g. 1 -> Integer.valueOf(1)). Additionally,
     * String is wrapped into quotes (e.g. Hello -> "Hello").
     *
     * @param argument the argument to wrap
     * @param type the expected type of the argument
     * @return the wrapped argument
     */
    private String wrap(String argument, Class<?> type)
    {
        if (!BeanshooterOption.INVOKE_NO_WRAP.getBool())
        {
            if (type == int.class)
                return String.format("Integer.valueOf(%s)", argument);

            if (type == long.class)
                return String.format("Long.valueOf(%s)", argument);

            if (type == short.class)
                return String.format("Short.valueOf(%s)", argument);

            if (type == double.class)
                return String.format("Double.valueOf(%s)", argument);

            if (type == float.class)
                return String.format("Float.valueOf(%s)", argument);

            if (type == byte.class)
                return String.format("Byte.valueOf(%s)", argument);

            if (type == boolean.class)
                return String.format("Boolean.valueOf(%s)", argument);

            if (type == char.class)
                return String.format("Char.valueOf(%s)", argument);

            if (type == String.class)
                return String.format("\"%s\"", argument.replace("\"", "\\\""));
        }

        return argument;
    }
}
