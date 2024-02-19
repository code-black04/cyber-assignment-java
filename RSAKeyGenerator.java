import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class RSAKeyGenerator {
    public static void main(String[] args) {

        try {
            if (args.length != 1) {
                System.err.println("Usage: java RSAKeyGen <<userid>>");
                System.exit(-1);
            }

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();

            FileOutputStream fos = new FileOutputStream(args[0] + ".pub");
            fos.write(kp.getPublic().getEncoded());
            fos.close();

            fos = new FileOutputStream(args[0] + ".prv");
            fos.write(kp.getPrivate().getEncoded());
            fos.close();
        } catch (java.lang.Exception e) {
            throw new RuntimeException(e);
        }
    }
}