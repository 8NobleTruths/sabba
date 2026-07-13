// A self-contained fixture for the Java prover. deep() recurses once per input byte with
// no depth limit, so a long enough input drives the recursion past the JVM stack and raises
// StackOverflowError. That is CWE-674, uncontrolled recursion, an input-driven stack
// exhaustion, the same class the C oracle proved on cJSON.
public class Vuln {
    public static int deep(byte[] b, int i) {
        if (i >= b.length) {
            return i;
        }
        return deep(b, i + 1) + b[i];
    }
}
