import java.io.*;
import java.net.*;
import java.util.*;

public class MeetingRoomServer {
    //Port 12345 for localhost connection between client and server
	private static final int PORT = 12345;
	//Text files being used that hold authorized logins and scheduled meeting times/available meeting times
    private static final String LOGIN_CREDS_FILE = "LoginCreds.txt";
    private static final String MEETING_TIMES_FILE = "MeetingTimes.txt";

    public static void main(String[] args) {
        //Print out that server is up and waiting for response from client
    	try (ServerSocket server = new ServerSocket(PORT)) {
            System.out.println("Meeting Room Server up and running, waiting on port " + PORT);

            while (true) {
                Socket socket = server.accept();
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                //Decrypt the LoginInfo from the Client
                String encryptedLoginInfo = in.readUTF();
                String decryptedLoginInfo = EncryptDecrypt.decrypt(encryptedLoginInfo);
                //Split the decrypted login info into the username and password pieces
                String[] loginCreds = decryptedLoginInfo.split(":");
                String username = loginCreds[0];
                String password = loginCreds[1];
                //Check if the username password combination matches an authorized credential in LoginCreds.txt
                boolean loginSuccess = checkLoginCredentials(username, password);
                out.writeUTF(loginSuccess ? "SUCCESS" : "FAIL");
                //If successful but no available times send no available times message, otherwise send available time slots
                if (loginSuccess) {
                    String meetingTimes = getMeetingTimes();
                    if (meetingTimes.equals("")) {
                        out.writeUTF("No available times, try again later.");
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
    
    //Function to check if the login credentials received from the client match authorized credentials in txt file
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
    //Check for open time slots to send to the client as possible reservations
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
            System.out.println("Error reading MeetingTimes.txt file");
        }
        return sb.toString();
    }
    //Function to write the time slot reservation to the MeetingTimes.txt file with timeslot:username
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
