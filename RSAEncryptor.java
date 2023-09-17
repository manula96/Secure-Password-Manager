import java.math.BigInteger;

public class RSAEncryptor {
    private BigInteger n;
    private BigInteger e;

    public RSAEncryptor(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
    }

    public BigInteger encryptPassword(String password) {
        byte[] passwordBytes = password.getBytes();
        BigInteger plaintext = new BigInteger(passwordBytes);
        BigInteger ciphertext = fastModularExponentiation(plaintext,e, n);
        //System.out.println(new String("ciphertext is: "+ciphertext));
        //BigInteger ciphertext = plaintext.modPow(e, n);

        return ciphertext;
    }

    public static BigInteger fastModularExponentiation(BigInteger base, BigInteger exponent,
                                                       BigInteger modulus) {
        BigInteger result = BigInteger.ONE;
        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            if (exponent.testBit(0)) {
                result = result.multiply(base).mod(modulus);
            }
            base = base.multiply(base).mod(modulus);
            exponent = exponent.shiftRight(1);
        }
        return result;
    }
}
