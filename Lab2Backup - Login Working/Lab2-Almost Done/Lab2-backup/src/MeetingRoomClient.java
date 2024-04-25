import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class MeetingRoomClient {
    private static final String HOST = "localhost";
    private static final int PORT = 1234;

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        int attempts = 5;
        while (attempts > 0) {
            System.out.print("Enter username: ");
            String username = sc.nextLine();

            System.out.print("Enter password: ");
            String password = sc.nextLine();

            String loginInfo = username + ":" + password;
            String encryptedLoginInfo = EncryptDecrypt.encrypt(loginInfo);

            try (Socket socket = new Socket(HOST, PORT)) {
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());

                out.writeUTF(encryptedLoginInfo);
                String response = in.readUTF();

                if (response.equals("SUCCESS")) {
                    System.out.println("Login successful");
                    String availableMeetingTimes = in.readUTF();
                    if (availableMeetingTimes.equals("No available times")) {
                        System.out.println("No available times");
                        System.exit(0);
                    }
                    System.out.println("Available meeting times:\n" + availableMeetingTimes);

                    List<String> availableTimesList = Arrays.asList(availableMeetingTimes.split("\n"));
                    String desiredTime;
                    do {
                        System.out.print("Enter desired meeting time: ");
                        desiredTime = sc.nextLine();
                        if (!availableTimesList.contains(desiredTime)) {
                            System.out.println("Invalid time, please enter a valid time from the list");
                        }
                    } while (!availableTimesList.contains(desiredTime));

                    out.writeUTF(desiredTime);
                    System.out.println("Meeting reserved at " + desiredTime + " under name " + username);
                    break;
                } else {
                    System.out.println("Login failed, try again");
                    attempts--;
                }
            } catch (Exception e) {
                System.out.println("Error connecting to server");
            }
        }
        if (attempts == 0) {
            System.out.println("Max login attempts reached. Exiting");
        }
    }
}
