import java.io.*;
import java.net.*;
import java.util.*;

public class MeetingRoomServer {
    private static final int PORT = 1234;
    private static final String LOGIN_CREDS_FILE = "LoginCreds.txt";

    public static void main(String[] args) {
        try (ServerSocket server = new ServerSocket(PORT)) {
            System.out.println("Server up and running, waiting for encrypted messages on port " + PORT);

            int attemptNumber = 1;
            while (true) {
                Socket socket = server.accept();
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());

                String encryptedLoginInfo = in.readUTF();
                String decryptedLoginInfo = EncryptDecrypt.decrypt(encryptedLoginInfo);

                String[] loginCreds = decryptedLoginInfo.split(":");
                String username = loginCreds[0];
                String password = loginCreds[1];

                boolean loginSuccess = checkLoginCredentials(username, password);
                out.writeUTF(loginSuccess ? "SUCCESS" : "FAIL");
                System.out.println("Login attempt " + attemptNumber + ": " + (loginSuccess ? "SUCCESS" : "FAIL"));

                socket.close();
                attemptNumber++;
            }
            
        } catch (Exception e) {
            System.out.println("Error setting up server");
        }
    }

    private static boolean checkLoginCredentials(String username, String password) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(LOGIN_CREDS_FILE));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] creds = line.split(":");
                if (creds[0].equals(username) && creds[1].equals(password)) {
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            System.out.println("Error reading login credentials file");
        }
        return false;
    }
}
