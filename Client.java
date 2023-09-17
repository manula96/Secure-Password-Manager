import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;

import static java.lang.System.in;
import static java.lang.System.out;

/**
 * A password manager client.
 * You will need to give it an interface with the options to send the server a password to store, to
 * get a stored password from the server, and to end the programs. You will also have to implement RSA
 * and use it correctly so that the server and any possible interceptor can never read the passwords.
 */
public class Client {

    /**
     * Send and receive a message in bytes to the specified host at the specified port.
     *
     * @param host string stating the name or ip address of the server
     * @param port int stating the port number of the server
     * @param message byte array containing the message to send to the server
     * @return a byte array containing the message that is received back from the server
     */
    public static byte[] sendReceive(String hostname, int port, byte[] message) {
        try (
            Socket s = new Socket(hostname, port);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            DataInputStream in = new DataInputStream(s.getInputStream())
        ) {
            out.write(message);  // Send the message to the server
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte buffer[] = new byte[1024];
            baos.write(buffer, 0, in.read(buffer));  // Receive a message from the server
            return buffer;
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }


    public static void main(String[] args) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        String hostname = "localhost";
        int port = 22500;
        //System.setProperty("javax.net.debug", "all");
        System.setProperty("javax.net.ssl.trustStore", "Certs/truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", Variables.Password);
        KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
        clientKeyStore.load(ClassLoader.getSystemResourceAsStream("Certs/Client.pfx"), Variables.Password.toCharArray());

        // Initialize the KeyManagerFactory with the client's key store
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(clientKeyStore, Variables.Password.toCharArray());

        // Create an SSL context with a custom TrustManager
        SSLContext sslContext = SSLContext.getInstance("SSL");

        // Load the CA certificate
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        char[] trustStorePassword = Variables.Password.toCharArray();
        trustStore.load(ClassLoader.getSystemResourceAsStream("Certs/Barry.p12"), trustStorePassword);
        //trustStore.load(ClassLoader.getSystemResourceAsStream("Certs/truststore.jks"), trustStorePassword);

        // Create a TrustManagerFactory for the CA trust store
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        // Initialize the SSL context with the client's key and trust managers
        sslContext.init(
                keyManagerFactory.getKeyManagers(),
                trustManagerFactory.getTrustManagers(),
                null
        );

        // Create an SSL socket factory
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

        try {
            //Socket socket = new Socket(hostname, port);
            Scanner scanner = new Scanner(System.in);
            boolean end = false;
            // Display options to the user
            System.out.println("\nWelcome to the SENG2250 password manager client!\nYou have the following options:");
            System.out.println("- store <website> <password>");
            System.out.println("- get <website>");
            System.out.println("- end");


            while (!end) {
                // Create an SSL socket
                SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(hostname, port);
                //System.out.println("Checkpoint 6");

                System.out.print(">>> "); // Display the prompt
                String userInput = scanner.nextLine().trim(); // Read user input

                if (userInput.startsWith("store ")) {
                    String[] parts = userInput.split(" ");
                    if (parts.length == 3) {
                        // Authenticate with the server using the client certificate and private key
                        socket.startHandshake();

                        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                        DataInputStream in = new DataInputStream(socket.getInputStream());

                        // Send the user's command to the server
                        out.write(userInput.getBytes());
                        out.flush(); // Make sure the data is sent immediately

                        // Receive and display the server's response
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        byte buffer[] = new byte[1024];

                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        baos.write(buffer, 0, bytesRead);
                        if (in.available() == 0) {
                            break; // Read until there is no more data available
                        }
                    }
                    String response = new String(baos.toByteArray(), 0, baos.size());
                    System.out.println(response);

                    } else {
                        System.out.println("Invalid 'store' command format. Please follow the format: store <website> <password>");
                    }


                } else if (userInput.startsWith("get ")) {
                    String[] parts = userInput.split(" ");
                    if (parts.length == 2) {
                        // Authenticate with the server using the client certificate and private key
                        socket.startHandshake();

                        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                        DataInputStream in = new DataInputStream(socket.getInputStream());

                        // Send the user's command to the server
                        out.write(userInput.getBytes());
                        out.flush(); // Make sure the data is sent immediately

                        // Receive and display the server's response
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        byte buffer[] = new byte[1024];

                        int bytesRead;
                        while ((bytesRead = in.read(buffer)) != -1) {
                            baos.write(buffer, 0, bytesRead);
                            if (in.available() == 0) {
                                break; // Read until there is no more data available
                            }
                        }
                        String response = new String(baos.toByteArray(), 0, baos.size());
                        System.out.println(response);

                    } else {
                        System.out.println("Invalid 'get' command format. Please follow the format: get <website>");
                    }
                } else if (userInput.equals("end")) {
                    // Authenticate with the server using the client certificate and private key
                    socket.startHandshake();

                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream());

                    // Send the "end" command to the server
                    out.write(userInput.getBytes());
                    out.flush(); // Make sure the data is sent immediately
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte buffer[] = new byte[1024];

                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        baos.write(buffer, 0, bytesRead);
                        if (in.available() == 0) {
                            break; // Read until there is no more data available
                        }
                    }
                    String response = new String(baos.toByteArray(), 0, baos.size());
                    System.out.println(response);
                    end = true;
                }
                else {
                    System.out.println("Invalid command. Please follow the format: store/get/end");
                }
            }

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
            System.err.println("\n *** Handshake failed. Server did not trust the connection ***\n");
            // Exit the program without errors
            System.exit(0);
        }

    }

}
