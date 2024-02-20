import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * @Citations
 * Referenced official Java documents:
 *      - Socket Programming
 *      - DataInputStream
 *      - DataOutputStream
 *      - Exceptions
 *      - Javax
 *      - Java Security library
 *      - Java Utility Library
 *      - Java Data Structures
 *      - Java Time and Date
 *      - Java Nio library
 *      - Java Security specs
 *      - Java Files read & write operations
 * <b>Note:</b> All the imports are also included
 */
public class CommonUtils {
    public static void callCloseSocketAndStreams(DataInputStream dataInputStream, DataOutputStream dataOutputStream, Socket s) throws Exception {
        dataInputStream.close();
        dataOutputStream.close();
        s.close();
    }

    public static String generateMD5Hash(String input) {
        try {
            String appendWithPrependKey = "gfhk2024:".concat(input);
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashInBytes = md.digest(appendWithPrependKey.getBytes());
            return byteArraytoHexString(hashInBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 hashing algorithm not found");
        }
    }

    //byte array to hex string conversion
    public static String byteArraytoHexString(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    //To create signature using sender's private key
    public static byte[] createSignature(String contentSent, String privateKeyName) throws Exception {
        // create signature
        PrivateKey prvKey = readPrivateKey(privateKeyName);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(prvKey);
        sig.update(contentSent.getBytes());
        return sig.sign();
    }

    //To verify signature by recipient using sender's public key
    public static Boolean verifySignature(String contentReceived, String publicKeyName, byte[] signatureReceived) throws Exception {
        PublicKey pubKey = readPublicKey(publicKeyName);
        Signature sig = Signature.getInstance("SHA256withRSA");
        // verify signature
        sig.initVerify(pubKey);
        sig.update(contentReceived.getBytes());
        return sig.verify(signatureReceived);
    }

    //To Read Private Key
    public static PrivateKey readPrivateKey(String userId) throws Exception {
        File f = new File(userId + ".prv");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);
        return privateKey;
    }

    //To Read Public Key
    public static PublicKey readPublicKey(String userId) throws Exception {
        File f = new File(userId + ".pub");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }

    public static byte[] encryptMessageWithPublicKey(String messageToBeEncrypted, String publicKeyName) throws BadPaddingException, Exception {
        try {
            Cipher encryptedCipher = Cipher.getInstance("RSA");
            PublicKey publicKey = readPublicKey(publicKeyName);
            if (publicKey == null) {
                throw new IllegalArgumentException("Public key not found for user: " + publicKeyName);
            }
            encryptedCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] secretMessageBytes = messageToBeEncrypted.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedMessageBytes = encryptedCipher.doFinal(secretMessageBytes);
            return encryptedMessageBytes;
        } catch (Exception e) {
            throw new Exception("Encryption failed");
        }
    }

    public static String decryptMessageWithPrivate(byte[] encryptedMessageBytes, String userId) throws BadPaddingException, Exception {
        try {
            Cipher decryptCipher = Cipher.getInstance("RSA");
            PrivateKey privateKey = readPrivateKey(userId);
            if (privateKey == null) {
                throw new IllegalArgumentException("Private key not found for user: " + userId);
            }
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
            String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
            return decryptedMessage;
        } catch (Exception e) {
            throw new Exception("Decryption failed");
        }
    }

    public static String writeFormattedTimestamp(long timestamp) {
        try {
            LocalDateTime localDateTime = LocalDateTime.ofEpochSecond(timestamp, 0, ZoneOffset.UTC);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss 'GMT' yyyy", Locale.ENGLISH);
            String formattedTimestamp = formatter.format(localDateTime);
            return formattedTimestamp;
        } catch (java.lang.Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
        return "";
    }
}
