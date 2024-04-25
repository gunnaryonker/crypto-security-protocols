import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class EncryptDecrypt {

    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] encrypt(String data, String publicKey, String paddingType) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/" + paddingType);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey, String paddingType) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/" + paddingType);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data, String base64PrivateKey, String paddingType) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
    	byte[] decodedData = Base64.getDecoder().decode(data.getBytes());
    	PrivateKey privateKey = getPrivateKey(base64PrivateKey);
    	return decrypt(decodedData, privateKey, paddingType);
    	}
    public static void main(String[] args) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Scanner scanner = new Scanner(System.in);
        
        String inputOption = "";
        
        while (true) {
            System.out.println("Enter option: Encrypt, Decrypt, or Both");
            String option = scanner.nextLine();
            
            //Encrypt data from either keyboard entry or text file input
            if (option.equalsIgnoreCase("Encrypt")) {
            	while (!inputOption.equalsIgnoreCase("keyboard") && !inputOption.equalsIgnoreCase("file")) {
                    System.out.println("Encrypt from keyboard entry or file input? (keyboard/file):");
                    inputOption = scanner.nextLine();
                    if (!inputOption.equalsIgnoreCase("keyboard") && !inputOption.equalsIgnoreCase("file")) {
                        System.out.println("Invalid entry option, please try again.");
                    }
                }
                
                String data = "";
                if (inputOption.equalsIgnoreCase("keyboard")) {
                    System.out.println("Enter the data to be encrypted:");
                    data = scanner.nextLine();
                } else if (inputOption.equalsIgnoreCase("file")) {
                    System.out.println("Enter the name of the file(Ex. Textfile.txt):");
                    String fileName = scanner.nextLine();
                    try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            data += line;
                        }
                    } catch (IOException e) {
                        System.out.println("Error reading file: " + e.getMessage());
                    }
                } else {
                    System.out.println("Invalid entry option, please try again.");
                    return;
                }
                
                String publicKey = "";
                String privateKey = "";

                try (BufferedReader br = new BufferedReader(new FileReader("PublicKey.txt"))) {
                    publicKey = br.readLine();
                } catch (IOException e) {
                    System.out.println("Error reading public key file: " + e.getMessage());
                }

                try (BufferedReader br = new BufferedReader(new FileReader("PrivateKey.txt"))) {
                    privateKey = br.readLine();
                } catch (IOException e) {
                    System.out.println("Error reading private key file: " + e.getMessage());
                }
                
                String paddingType = "";
                while (!paddingType.equals("OAEP") && !paddingType.equals("PKCS1")) {
                    System.out.println("Enter the padding type (OAEP, PKCS1):");
                    paddingType = scanner.nextLine();
                    if (!paddingType.equals("OAEP") && !paddingType.equals("PKCS1")) {
                        System.out.println("Invalid padding type, please try again.");
                    }
                }

                if (paddingType.equals("OAEP")) {
                    paddingType = "OAEPWithSHA1AndMGF1Padding";
                } else if (paddingType.equals("PKCS1")) {
                    paddingType = "PKCS1Padding";
                }
                
                byte[] encryptedData = encrypt(data, publicKey, paddingType);
                String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);
                System.out.println("\nEntry encrypted using RSA/ECB/" + paddingType );
                System.out.println("Encrypted Data (Base64 Encoded): " + encryptedDataBase64);

                if (inputOption.equalsIgnoreCase("file") || inputOption.equalsIgnoreCase("keyboard")) {
                    try (PrintWriter writer = new PrintWriter("Ciphertext.txt")) {
                        writer.println(encryptedDataBase64);
                        System.out.println("Encrypted data written to Ciphertext.txt");
                    } catch (FileNotFoundException e) {
                        System.out.println("Error creating Ciphertext file: " + e.getMessage());
                    }
                }
            //Decrypt from either keyboard entry of ciphertext or file entry of ciphertext
            } else if (option.equalsIgnoreCase("Decrypt")) {
                while (!inputOption.equalsIgnoreCase("keyboard") && !inputOption.equalsIgnoreCase("file")) {
                    System.out.println("Decrypt from keyboard entry or file input? (keyboard/file):");
                    inputOption = scanner.nextLine();
                    if (!inputOption.equalsIgnoreCase("keyboard") && !inputOption.equalsIgnoreCase("file")) {
                        System.out.println("Invalid entry option, please try again.");
                    }
                }
                
                String ciphertext = "";
                if (inputOption.equalsIgnoreCase("keyboard")) {
                    System.out.println("Enter the data to be decrypted:");
                    ciphertext = scanner.nextLine();
                } else if (inputOption.equalsIgnoreCase("file")) {
                    System.out.println("Enter the name of the file(Ex. Textfile.txt):");
                    String fileName = scanner.nextLine();
                    try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            ciphertext += line;
                        }
                    } catch (IOException e) {
                        System.out.println("Error reading file: " + e.getMessage());
                    }
                } else {
                    System.out.println("Invalid entry option, please try again.");
                    return;
                }
                
                String privateKey = "";

                try (BufferedReader br = new BufferedReader(new FileReader("PrivateKey.txt"))) {
                    privateKey = br.readLine();
                } catch (IOException e) {
                    System.out.println("Error reading private key file: " + e.getMessage());
                }
                
                String paddingType = "";
                while (!paddingType.equals("OAEP") && !paddingType.equals("PKCS1")) {
                    System.out.println("Enter the padding type (OAEP, PKCS1):");
                    paddingType = scanner.nextLine();
                    if (!paddingType.equals("OAEP") && !paddingType.equals("PKCS1")) {
                        System.out.println("Invalid padding type, please try again.");
                    }
                }

                if (paddingType.equals("OAEP")) {
                    paddingType = "OAEPWithSHA1AndMGF1Padding";
                } else if (paddingType.equals("PKCS1")) {
                    paddingType = "PKCS1Padding";
                }
                
                System.out.println("\nEntry decrypted using RSA/ECB/" + paddingType );
                System.out.println("Encrypted Data (Base64 Encoded): " + ciphertext);
                
                String decryptedData = decrypt(ciphertext, privateKey, paddingType);
                System.out.println("\nDecrypted Data: " + decryptedData);
                
            //Encrypt and decrypt any given data
            } else if (option.equalsIgnoreCase("Both")) {
            	 while (!inputOption.equalsIgnoreCase("keyboard") && !inputOption.equalsIgnoreCase("file")) {
                     System.out.println("Encrypt from keyboard entry or file input? (keyboard/file):");
                     inputOption = scanner.nextLine();
                     if (!inputOption.equalsIgnoreCase("keyboard") && !inputOption.equalsIgnoreCase("file")) {
                         System.out.println("Invalid entry option, please try again.");
                     }
                 }
                 
                 String data = "";
                 if (inputOption.equalsIgnoreCase("keyboard")) {
                     System.out.println("Enter the data to be encrypted:");
                     data = scanner.nextLine();
                 } else if (inputOption.equalsIgnoreCase("file")) {
                     System.out.println("Enter the name of the file(Ex. Textfile.txt):");
                     String fileName = scanner.nextLine();
                     try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
                         String line;
                         while ((line = br.readLine()) != null) {
                             data += line;
                         }
                     } catch (IOException e) {
                         System.out.println("Error reading file: " + e.getMessage());
                     }
                 } else {
                     System.out.println("Invalid entry option, please try again.");
                     return;
                 }
                 
                 String publicKey = "";
                 String privateKey = "";

                 try (BufferedReader br = new BufferedReader(new FileReader("PublicKey.txt"))) {
                     publicKey = br.readLine();
                 } catch (IOException e) {
                     System.out.println("Error reading public key file: " + e.getMessage());
                 }

                 try (BufferedReader br = new BufferedReader(new FileReader("PrivateKey.txt"))) {
                     privateKey = br.readLine();
                 } catch (IOException e) {
                     System.out.println("Error reading private key file: " + e.getMessage());
                 }
                 
                 String paddingType = "";
                 while (!paddingType.equals("OAEP") && !paddingType.equals("PKCS1")) {
                     System.out.println("Enter the padding type (OAEP, PKCS1):");
                     paddingType = scanner.nextLine();
                     if (!paddingType.equals("OAEP") && !paddingType.equals("PKCS1")) {
                         System.out.println("Invalid padding type, please try again.");
                     }
                 }

                 if (paddingType.equals("OAEP")) {
                     paddingType = "OAEPWithSHA1AndMGF1Padding";
                 } else if (paddingType.equals("PKCS1")) {
                     paddingType = "PKCS1Padding";
                 }
                 
                 byte[] encryptedData = encrypt(data, publicKey, paddingType);
                 String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);
                 System.out.println("\nEntry encrypted using RSA/ECB/" + paddingType );
                 System.out.println("Encrypted Data (Base64 Encoded): " + encryptedDataBase64);

                 if (inputOption.equalsIgnoreCase("file") || inputOption.equalsIgnoreCase("keyboard")) {
                     try (PrintWriter writer = new PrintWriter("Ciphertext.txt")) {
                         writer.println(encryptedDataBase64);
                         System.out.println("Encrypted data written to Ciphertext.txt");
                     } catch (FileNotFoundException e) {
                         System.out.println("Error creating Ciphertext file: " + e.getMessage());
                     }
                 }
                 String decryptedData = decrypt(encryptedDataBase64, privateKey, paddingType);
                 System.out.println("\nDecrypted Data: " + decryptedData);
            } else {
                System.out.println("Invalid option, try again.");
                continue;
            }

            break;
        }
    }
}
