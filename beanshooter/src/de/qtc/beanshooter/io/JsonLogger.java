package de.qtc.beanshooter.io;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The JsonLogger class implements optional JSON Lines output for beanshooter. When enabled via the
 * global '--json' option, beanshooter emits machine readable result records (one JSON object per line)
 * that can be parsed with tools like jq. Each record contains at least a 'type' field that identifies
 * the kind of result (e.g. 'credentials', 'mbean', 'enum') and a 'time' field with an ISO-8601 timestamp.
 *
 * Records are written as they are produced (live), which makes it possible to consume beanshooter output
 * in a streaming fashion. When JSON output is sent to stdout, the human readable logging produced by the
 * {@link Logger} class is automatically redirected to stderr, so that stdout contains valid JSON Lines only.
 *
 * @author Olivier Cervello
 */
public class JsonLogger
{
    private static boolean enabled = false;
    private static PrintStream out = null;

    /**
     * Enable JSON Lines output. The destination is taken from the global '--json' option:
     *
     *   - null      -> JSON output disabled (default)
     *   - "-"       -> JSON output written to stdout (human readable logging redirected to stderr)
     *   - <path>    -> JSON output appended to the specified file
     *
     * @param destination value of the global '--json' option
     */
    public static void enable(String destination)
    {
        if (destination == null)
            return;

        if (destination.equals("-"))
        {
            out = System.out;
            Logger.redirectStdoutToStderr();
        }

        else
        {
            try
            {
                out = new PrintStream(new FileOutputStream(destination, true), true);
            }

            catch (IOException e)
            {
                Logger.eprintlnMixedYellow("Unable to open JSON output file", destination, "- disabling JSON output.");
                return;
            }
        }

        enabled = true;
    }

    /**
     * @return true if JSON Lines output is currently enabled
     */
    public static boolean isEnabled()
    {
        return enabled;
    }

    /**
     * Emit a single JSON Lines record. The provided key/value pairs are added to the record in order.
     * A 'type' and a 'time' field are always prepended automatically. This method is a no-op when JSON
     * output is disabled, so it is safe to call unconditionally from anywhere within beanshooter.
     *
     * @param type record type identifier (e.g. 'credentials', 'mbean', 'enum')
     * @param kv alternating key/value pairs to include within the record
     */
    public static synchronized void log(String type, Object... kv)
    {
        if (!enabled)
            return;

        Map<String,Object> record = new LinkedHashMap<String,Object>();
        record.put("type", type);
        record.put("time", Instant.now().toString());

        for (int i = 0; i + 1 < kv.length; i += 2)
            record.put(String.valueOf(kv[i]), kv[i + 1]);

        out.println(serialize(record));
        out.flush();
    }

    /**
     * Serialize a map into a compact, single line JSON object.
     */
    private static String serialize(Map<String,Object> map)
    {
        StringBuilder builder = new StringBuilder();
        builder.append('{');

        boolean first = true;

        for (Map.Entry<String,Object> entry : map.entrySet())
        {
            if (!first)
                builder.append(',');

            first = false;

            builder.append(quote(entry.getKey()));
            builder.append(':');
            builder.append(serializeValue(entry.getValue()));
        }

        builder.append('}');
        return builder.toString();
    }

    /**
     * Serialize a single value into its JSON representation. Strings are quoted and escaped, numbers and
     * booleans are emitted verbatim, null becomes 'null' and everything else is rendered via toString().
     */
    private static String serializeValue(Object value)
    {
        if (value == null)
            return "null";

        if (value instanceof Number || value instanceof Boolean)
            return value.toString();

        return quote(value.toString());
    }

    /**
     * Quote and escape a string according to the JSON specification.
     */
    private static String quote(String value)
    {
        StringBuilder builder = new StringBuilder();
        builder.append('"');

        for (int i = 0; i < value.length(); i++)
        {
            char c = value.charAt(i);

            switch (c)
            {
                case '"':
                    builder.append("\\\"");
                    break;
                case '\\':
                    builder.append("\\\\");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                case '\b':
                    builder.append("\\b");
                    break;
                case '\f':
                    builder.append("\\f");
                    break;
                default:
                    if (c < 0x20)
                        builder.append(String.format("\\u%04x", (int) c));
                    else
                        builder.append(c);
            }
        }

        builder.append('"');
        return builder.toString();
    }
}
