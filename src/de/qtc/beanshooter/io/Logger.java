package de.qtc.beanshooter.io;

public class Logger {

    private static String ANSI_RESET = "\u001B[0m";
    private static String ANSI_BLACK = "\u001B[30m";
    private static String ANSI_RED = "\u001B[31m";
    private static String ANSI_GREEN = "\u001B[32m";
    private static String ANSI_YELLOW = "\u001B[33m";
    private static String ANSI_BLUE = "\u001B[34m";
    private static String ANSI_PURPLE = "\u001B[35m";
    private static String ANSI_CYAN = "\u001B[36m";
    private static String ANSI_WHITE = "\u001B[37m";

    private static int indent = 0;
    private static String infoPrefix = "[+]";
    private static String errorPrefix = "[-]";

    public static void disableColor() {
        ANSI_RESET = "";
        ANSI_BLACK = "";
        ANSI_RED = "";
        ANSI_GREEN = "";
        ANSI_YELLOW = "";
        ANSI_BLUE = "";
        ANSI_PURPLE = "";
        ANSI_CYAN = "";
        ANSI_WHITE = "";
    }

    public static void print(String msg) {
        System.out.print(infoPrefix + Logger.getIndent() + msg);
    }

    public static void eprint(String msg) {
        System.err.print(errorPrefix + Logger.getIndent() + msg);
    }

    public static void eprint_ye(String msg) {
        System.err.print(errorPrefix + Logger.getIndent() + ANSI_YELLOW + msg + ANSI_RESET);
    }

    public static void eprint_bl(String msg) {
        System.err.print(errorPrefix + Logger.getIndent() + ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void print_bl(String msg) {
        System.out.print(infoPrefix + Logger.getIndent() + ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void print_ye(String msg) {
        System.out.print(infoPrefix + Logger.getIndent() + ANSI_YELLOW + msg + ANSI_RESET);
    }

    public static void println(String msg) {
        System.out.println(infoPrefix + Logger.getIndent() + msg);
    }

    public static void printlnPlain(String msg) {
        System.out.println(msg);
    }

    public static void eprintln(String msg) {
        System.err.println(errorPrefix + Logger.getIndent() + msg);
    }

    public static void eprintlnPlain(String msg) {
        System.err.println(msg);
    }

    public static void println_bl(String msg) {
        System.out.println(infoPrefix + Logger.getIndent() + ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void eprintln_bl(String msg) {
        System.err.println(errorPrefix + Logger.getIndent() + ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void println_ye(String msg) {
        System.out.println(infoPrefix + Logger.getIndent() + ANSI_YELLOW + msg + ANSI_RESET);
    }

    public static void eprintln_ye(String msg) {
        System.err.println(errorPrefix + Logger.getIndent() + ANSI_YELLOW + msg + ANSI_RESET);
    }

    public static void printPlain(String msg) {
        System.out.print(msg);
    }

    public static void printPlain_ye(String msg) {
        System.out.print(ANSI_YELLOW + msg + ANSI_RESET);
    }

    public static void printPlain_bl(String msg) {
        System.out.print(ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void printlnPlain_bl(String msg) {
        System.out.println(ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void eprintlnPlain_bl(String msg) {
        System.err.println(ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void printlnPlain_ye(String msg) {
        System.out.println(ANSI_YELLOW + msg + ANSI_RESET);
    }

    public static void eprintlnPlain_ye(String msg) {
        System.err.println(ANSI_YELLOW + msg + ANSI_RESET);
    }

    public static void increaseIndent() {
        indent += 1;
    }

    public static void decreaseIndent() {
        indent -= 1;
    }

    public static String getIndent() {
        return " " + new String(new char[indent]).replace("\0", "\t");
    }
}
