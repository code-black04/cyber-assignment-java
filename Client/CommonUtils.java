import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class CommonUtils {
    public static void callCloseSocketAndStreams(DataInputStream dataInputStream, DataOutputStream dataOutputStream, Socket s) throws IOException {
        dataInputStream.close();
        dataOutputStream.close();
        s.close();
    }

    public static byte[] byteStreamToHandleString(DataInputStream dataInputStream, int length) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[length]; // Temporary buffer
        while ((nRead = dataInputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        buffer.flush();
        byte[] allData = buffer.toByteArray();
        System.out.println("ALL Data Length : " + allData.length);
        return allData;
    }


    public static String toHexString(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static String generateMD5Hash(String input) {
        try {
            String appendWithPrependKey = "gfhk2024:".concat(input);
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashInBytes = md.digest(appendWithPrependKey.getBytes());
            return toHexString(hashInBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 hashing algorithm not found");
        }
    }

    public static byte[] createSignature(String contentSent, String privateKeyName) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
        // create signature
        PrivateKey prvKey = RSAUtils.readPrivateKey(privateKeyName);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(prvKey);
        sig.update(contentSent.getBytes());
        return sig.sign();
    }

    public static Boolean verifySignature(String contentReceived, String publicKeyName, byte[] signatureReceived) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        PublicKey pubKey = RSAUtils.readPublicKey(publicKeyName);
        Signature sig = Signature.getInstance("SHA256withRSA");
        // verify signature
        sig.initVerify(pubKey);
        sig.update(contentReceived.getBytes());
        return sig.verify(signatureReceived);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, InvalidKeySpecException {
        String input = "alice";
        byte[] createSign = CommonUtils.createSignature(input, "alice");
        System.out.println(CommonUtils.verifySignature(input, "bob", createSign));
    }
}
