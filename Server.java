import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.ServerSocket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;


/**
 * A password manager server.
 * You will need to give it the ability to correctly store passwords and to send them back to the
 * client when requested.
 */
public class Server {

    // Secure storage for passwords
    private static Map<String, BigInteger> passwordStorage = new HashMap<>();

    // Instances for RSA key generation and encryption/decryption
    private static RSAKeyGenerator rsaKeyGenerator;
    private static RSAEncryptor rsaEncryptor;
    private static RSADecryptor rsaDecryptor;



    public static void initializeRSA() {
        // Initialize RSA key generation
        rsaKeyGenerator = new RSAKeyGenerator();
        BigInteger n = rsaKeyGenerator.getN();
        BigInteger e = rsaKeyGenerator.getE();
        BigInteger d = rsaKeyGenerator.getD();

        // Initialize RSA encryption and decryption
        rsaEncryptor = new RSAEncryptor(n, e);
        rsaDecryptor = new RSADecryptor(n, d);
    }


    public static boolean handleMessage(Socket conn, byte[] data) {
        try (
            Scanner scanner = new Scanner(System.in);
            DataOutputStream out = new DataOutputStream(conn.getOutputStream());
            DataInputStream in = new DataInputStream(conn.getInputStream())
        ) {
            boolean end = false;
            String message = new String(data);
            if (message.startsWith("store")) {
                String[] parts = message.split(" ");

                    // Store the password securely
                    String website = parts[1];
                    String password = "";

                    //if the pass is a pass phrase
                    for (int i = 2; i < parts.length; i++) {
                        password += parts[i] + " "; // Concatenate all remaining parts as the password
                    }
                    password = password.trim(); // Remove trailing space

                    if (PasswordValidator.isPasswordValid(password)) {
                        // Encrypt the password using the server's public key
                        BigInteger encryptedPassword = rsaEncryptor.encryptPassword(password);

                        // Store the encrypted password securely
                        passwordStorage.put(website, encryptedPassword);

                        // Respond with success message
                        out.write("Password successfully stored".getBytes());
                    }
                 else {
                    out.write(("Password does not meet strength requirements.\n" +
                            "Should be min 8 characters long, atleast 1 uppercase letter," +
                            "1 integer and 1 special character needed \n").getBytes());
                }

            } else if (message.startsWith("get")) {
                String[] parts = message.split(" ");
                    // Retrieve and decrypt the password securely using RSA
                    String website = parts[1].trim();
                    // Retrieve and decrypt the password using the server's private key
                    BigInteger encryptedPassword = passwordStorage.get(website);
                    if (encryptedPassword != null) {
                        String decryptedPassword = rsaDecryptor.decryptPassword(encryptedPassword);
                        // Respond with the decrypted password
                        out.write(decryptedPassword.getBytes());
                    } else {
                        out.write("Password not found. Please check the website entered\n".getBytes());
                    }

            } else if (message.trim().equals("end")) {
                out.write("Bye!\n".getBytes());
                return true;
            }

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }

        return false;
    }

    private static SSLServerSocket serverSocket;
    public static void main(String[] args) throws CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, KeyManagementException {
        System.setProperty("javax.net.ssl.trustStore", "Certs/truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", Variables.Password);


        String hostname = "localhost";
        int port = 22500;  // Arbitrary non-privileged port
        boolean end = false;

        KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
        serverKeyStore.load(ClassLoader.getSystemResourceAsStream("Certs/Server.pfx"), Variables.Password.toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(serverKeyStore, Variables.Password.toCharArray());

        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, new java.security.SecureRandom());

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);
        serverSocket.setNeedClientAuth(true);
        System.out.format("Listening for a client on port %d\n", port);

        // Initialize RSA key generation and encryption/decryption
        initializeRSA();



        try (

                //ServerSocket serverSocket = new ServerSocket(port);
                Scanner scanner = new Scanner(System.in); // Initialize a Scanner for user input

        ) {
            do {
                SSLSocket socket = (SSLSocket) serverSocket.accept();;

                //------------- Client Authentication -------------------------
                SSLSession sslSession = socket.getSession();
                X509Certificate[] clientCertificates = (X509Certificate[]) sslSession.getPeerCertificates();
                for (Certificate certificate : clientCertificates) {
                    // If it's an X.509 certificate, you can cast it for further inspection
                    if (certificate instanceof X509Certificate) {
                        X509Certificate x509Certificate = (X509Certificate) certificate;
                        // Check if the certificate is expired
                        boolean isExpired = isCertificateExpired(x509Certificate);

                        // Check the issuer's name to verify it's issued by the CA with the name "Barry"
                        String issuerName = x509Certificate.getIssuerX500Principal().getName();
                        boolean isIssuerValid = issuerName.contains("CN=BarryCA");
                        if (!isIssuerValid || isExpired) {
                            // Certificate is NOT trusted
                            socket.close();
                            System.out.println("\n*** CA not trusted ***");
                            System.out.println("Client might be an intruder...\n"+ "Server is shutting down...\n");
                            System.exit(0);
                        }
                    }
                }

                //---------------
                System.out.format(
                    "Connected by %s:%d\n",
                    socket.getInetAddress().toString(),
                    socket.getPort()
                );
                DataInputStream in = new DataInputStream(socket.getInputStream());
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte data[] = new byte[1024];
                baos.write(data, 0, in.read(data));

                end = handleMessage(socket, data);
                in.close();
                socket.close();
            } while (!end);

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
    private static boolean isCertificateExpired(X509Certificate certificate) {
        try {
            Date currentDate = new Date();

            // Check if the certificate is expired by comparing the current date with the certificate's notAfter date
            certificate.checkValidity(currentDate);

            return false;
        } catch (Exception e) {
            return true;
        }
    }
}