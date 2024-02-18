import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtils {

    public static PrivateKey readPrivateKey(String userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File f = new File("keys/" + userId + ".prv");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);
        return privateKey;
    }

    public static PublicKey readPublicKey(String userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File f = new File("keys/" + userId + ".pub");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }

    public static byte[] encryptMessageWithPublicKey(String messageToBeEncrypted, String publicKeyName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptedCipher = Cipher.getInstance("RSA");
        encryptedCipher.init(Cipher.ENCRYPT_MODE, readPublicKey(publicKeyName));
        byte[] secretMessageBytes = messageToBeEncrypted.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptedCipher.doFinal(secretMessageBytes);
        return encryptedMessageBytes;
    }

    public static String decryptMessageWithPrivate(byte[] encryptedMessageBytes, String userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, readPrivateKey(userId));
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
        return decryptedMessage;
    }

    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        byte[] encryptMessage = encryptMessageWithPublicKey("Hye testestsetestsettetstet", "server");
        System.out.println("Encrypt " + encryptMessage);
        String string = new String(encryptMessage);
        String decryptMessage = decryptMessageWithPrivate(encryptMessage, "server");
        System.out.println("Decrypt " + decryptMessage);
    }

}
