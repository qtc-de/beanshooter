package de.qtc.beanshooter.plugin.providers;

import java.lang.reflect.Method;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.plugin.IArgumentProvider;
import de.qtc.beanshooter.utils.Utils;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;

public class ArgumentProvider implements IArgumentProvider
{
    /**
     * This function performs basically an eval operation on the user specified argumentString. The argument string is
     * inserted into the following expression: return new Object[] { " + argumentString + "};
     * This expression is evaluated and the resulting Object array is returned by this function. For this to work it is
     * important that all arguments within the argumentString are valid Java Object definitions. E.g. one has to use
     * new Integer(5) instead of a plain 5.
     */
     public Object[] getArgumentArray(String argumentString)
     {
         Object[] result = null;
         ClassPool pool = ClassPool.getDefault();

         if( argumentString.isEmpty() )
             return null;

         try {
             CtClass evaluator = pool.makeClass("de.qtc.rmg.plugin.DefaultProviderEval");
             String evalFunction = "public static Object[] eval() {"
                                 + "        return new Object[] { " + argumentString + "};"
                                 + "}";

             CtMethod me = CtNewMethod.make(evalFunction, evaluator);
             evaluator.addMethod(me);
             Class<?> evalClass = evaluator.toClass();

             Method m = evalClass.getDeclaredMethods()[0];
             result = (Object[]) m.invoke(evalClass, (Object[])null);

         } catch(VerifyError | CannotCompileException e) {
             Logger.eprintlnMixedYellow("Specified argument string", argumentString, "is invalid.");
             Logger.eprintlnMixedBlue("Argument string has to be a valid Java expression like:", "'\"id\", new Integer(4)'.");
             Logger.eprintMixedYellow("Make sure that each argument is an", "Object", "not a ");
             Logger.printlnPlainYellow("Primitive.");
             ExceptionHandler.showStackTrace(e);
             Utils.exit();

         } catch (Exception e) {
             ExceptionHandler.unexpectedException(e, "argument array", "generation", true);
         }

         return result;
     }
}
