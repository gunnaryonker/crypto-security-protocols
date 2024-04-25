import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class MeetingRoomClient {
	//Port 12345 to connect to localhost server
    private static final String HOST = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        //If 5 failed attempts then program will exit
        while (true) {
            int attempts = 5;
            while (attempts > 0) {
            	//User enters username and password
                System.out.print("Enter username: ");
                String username = sc.nextLine();

                System.out.print("Enter password: ");
                String password = sc.nextLine();
                //Create loginInfo with username and password, then encrypt and send to server
                String loginInfo = username + ":" + password;
                String encryptedLoginInfo = EncryptDecrypt.encrypt(loginInfo);

                try (Socket socket = new Socket(HOST, PORT)) {
                    DataInputStream in = new DataInputStream(socket.getInputStream());
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());

                    out.writeUTF(encryptedLoginInfo);
                    String response = in.readUTF();
                    //Check for response from server if login was approved or not, if successful show user available times(if any)
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
                            //If user enters an invalid time, do not accept and ask for re-entry
                            if (!availableTimesList.contains(desiredTime)) {
                                System.out.println("Invalid time, please enter a valid time from the list");
                            }
                        } while (!availableTimesList.contains(desiredTime));

                        out.writeUTF(desiredTime);
                        //If meeting time is successfully reserved, print out time slot and the username it is under
                        System.out.println("Meeting reserved at " + desiredTime + " under name " + username);
                        break;
                    } else {
                    	//If login is unsuccessful from server, prompt user to try again until 5 failed attempts
                        System.out.println("Login failed, try again");
                        attempts--;
                    }
                } catch (Exception e) {
                    System.out.println("Error connecting to server");
                }
            }
            if (attempts == 0) {
            	//Exit if user reaches 5 failed attempts
                System.out.println("Max login attempts reached, try again later.");
                System.exit(0);
            }
            //Prompt user to make another reservation
            System.out.print("Do you want to make another reservation (y/n)? ");
            String answer = sc.nextLine();
            //If user answer with "n" then exit the program, if user answers with "y" then start reservation process again
            if (!answer.equalsIgnoreCase("y")) {
                break;
            }
        }
    }
}
