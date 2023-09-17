import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
public class RSAKeyGenerator {
    private BigInteger p;
    private BigInteger q;
    private BigInteger n; // Modulus
    private BigInteger e; // Public exponent
    private BigInteger d; // Private exponent

    public RSAKeyGenerator() {
        // Generate random prime numbers p and q
        try (BufferedReader br = new BufferedReader(new FileReader("primes.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("p=")) {
                    p = new BigInteger(line.substring(2));
                } else if (line.startsWith("q=")) {
                    q = new BigInteger(line.substring(2));
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Compute n, φ(n), e, and d
        n = p.multiply(q);
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("65537"); // Common choice for e
        d = e.modInverse(phiN);
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getD() {
        return d;
    }
}
