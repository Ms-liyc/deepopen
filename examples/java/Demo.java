class Demo {
    void run(String name) {
        Runtime.getRuntime().exec("cmd /c echo " + name);
        java.util.Random random = new java.util.Random();
        java.io.ObjectInputStream in = new java.io.ObjectInputStream(System.in);
    }
}
