import java.io.*;
import java.net.*;
import java.util.*;

public class MeetingRoomServer {
    private static final int PORT = 1234;
    private static final String LOGIN_CREDS_FILE = "LoginCreds.txt";
    private static final String MEETING_TIMES_FILE = "MeetingTimes.txt";

    public static void main(String[] args) {
        try (ServerSocket server = new ServerSocket(PORT)) {
            System.out.println("Server up and running, waiting for encrypted messages on port " + PORT);

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

                if (loginSuccess) {
                    String meetingTimes = getMeetingTimes();
                    if (meetingTimes.equals("")) {
                        out.writeUTF("No available times");
                    } else {
                        out.writeUTF(meetingTimes);

                        String reservedTimeSlot = in.readUTF();
                        reserveTimeSlot(username, reservedTimeSlot);
                    }
                }

                socket.close();
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
            return false;
        } catch (Exception e) {
            System.out.println("Error checking login credentials");
            return false;
        }
    }

    private static String getMeetingTimes() {
        StringBuilder sb = new StringBuilder();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(MEETING_TIMES_FILE));
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.contains(":")) {
                    sb.append(line).append("\n");
                }
            }
            reader.close();
        } catch (Exception e) {
            System.out.println("Error reading meeting times file");
        }
        return sb.toString();
    }

    private static void reserveTimeSlot(String username, String reservedTimeSlot) {
        try {
            List<String> lines = new ArrayList<>();
            BufferedReader reader = new BufferedReader(new FileReader(MEETING_TIMES_FILE));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(reservedTimeSlot)) {
                    lines.add(reservedTimeSlot + ":" + username);
                } else {
                    lines.add(line);
                }
            }
            reader.close();
            BufferedWriter writer = new BufferedWriter(new FileWriter(MEETING_TIMES_FILE));
            for (String time : lines) {
                writer.write(time + "\n");
            }
            writer.close();
        } catch (Exception e) {
            System.out.println("Error reserving time slot");
        }
    }
}
