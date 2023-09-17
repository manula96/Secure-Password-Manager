import java.math.BigInteger;

public class RSADecryptor {
    private BigInteger n;
    private BigInteger d;

    public RSADecryptor(BigInteger n, BigInteger d) {
        this.n = n;
        this.d = d;
    }

    public String decryptPassword(BigInteger ciphertext) {
        BigInteger plaintext = ciphertext.modPow(d, n);
        byte[] passwordBytes = plaintext.toByteArray();
        return new String(passwordBytes);
    }
}
