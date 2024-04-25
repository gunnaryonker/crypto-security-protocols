import java.io.*;
import java.net.*;
import java.util.*;

public class MeetingRoomClient {
    private static final String HOST = "localhost";
    private static final int PORT = 1234;
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final String LOGIN_CREDS_FILE = "LoginCreds.txt";

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        int loginAttempts = 0;
        boolean loginSuccess = false;

        while (!loginSuccess && loginAttempts < MAX_LOGIN_ATTEMPTS) {
            System.out.print("Enter username: ");
            String username = sc.nextLine();
            System.out.print("Enter password: ");
            String password = sc.nextLine();

            try {
                Socket socket = new Socket(HOST, PORT);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream());

                // Encrypt the login information
                String loginInfo = EncryptDecrypt.encrypt(username + ":" + password);
                out.writeUTF(loginInfo);

                String response = in.readUTF();
                if (response.equals("SUCCESS")) {
                    System.out.println("Login successful");
                    loginSuccess = true;
                } else {
                    System.out.println("Login failed, please try again");
                }

                socket.close();
            } catch (Exception e) {
                System.out.println("Error communicating with server");
            }

            loginAttempts++;
        }

        if (!loginSuccess) {
            System.out.println("Too many login attempts, Program will exit.");
        }
    }
}
