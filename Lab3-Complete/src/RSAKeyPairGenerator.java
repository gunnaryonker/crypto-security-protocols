import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class RSAKeyPairGenerator {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        Scanner sc = new Scanner(System.in);
        int keyLength = 0;
        while (keyLength != 1024 && keyLength != 2048 && keyLength != 3072) {
            System.out.print("Enter the desired key length (1024, 2048, or 3072): ");
            keyLength = sc.nextInt();
        }
        keyGen.initialize(keyLength);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File("." + File.separator + path);
        File parentDirectory = new File(f.getParent());
        if (!parentDirectory.exists() && !parentDirectory.mkdirs()) {
            throw new IOException("Could not create parent directory");
        }

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        String publicKeyStr = Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded());
        String privateKeyStr = Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded());
        keyPairGenerator.writeToFile("PublicKey.txt", publicKeyStr.getBytes());
        keyPairGenerator.writeToFile("PrivateKey.txt", privateKeyStr.getBytes());
        System.out.println("Public Key: " + publicKeyStr);
        System.out.println("Private Key: " + privateKeyStr);
    }
}
