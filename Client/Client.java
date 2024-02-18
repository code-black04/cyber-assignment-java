import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Scanner;

public class Client {

    private String hostName;
    private String severPort;
    private String senderUserId;

    public Client(String hostName, String serverPort, String senderUserId) {
        this.hostName = hostName;
        this.severPort = serverPort;
        this.senderUserId = senderUserId;
    }

    private void init() {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                getMessageFromServer(new SendMessage(senderUserId, null, null, "get-message"));
                while (true) {
                    Scanner scanner = new Scanner(System.in);
                    System.out.println("Do you want to send a message? [y/n]: ");
                    String actionSelection = scanner.nextLine();
                    try {
                        writeMessageDetailsAndSend(actionSelection, scanner);
                    } catch (IOException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException |
                             NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        });
        thread.start();
    }

    private void writeMessageDetailsAndSend(String actionSelection, Scanner scanner) throws IOException, InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (actionSelection.equalsIgnoreCase("y")) {
            System.out.println("Enter the recipient userid: ");
            String recipientUserId = scanner.nextLine();
            System.out.println("Enter your message: ");
            String message = scanner.nextLine();
            sendMessage(message, recipientUserId);
        } else if (actionSelection.equalsIgnoreCase("n")) {
            System.exit(0);
        }
    }

    private void sendMessage(String message, String recipientUserId) {
        if (message != null) {
            try {
                byte[] encryptedRecipientUserIdBytes = RSAUtils.encryptMessageWithPublicKey(recipientUserId, "server");
                byte[] encryptedMessageBytes = RSAUtils.encryptMessageWithPublicKey(message, "server");
                sendMessageToServer(new SendMessage(senderUserId, encryptedRecipientUserIdBytes, encryptedMessageBytes, "send-message"));
            } catch (NoSuchPaddingException | IllegalBlockSizeException | IOException | NoSuchAlgorithmException |
                     InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        } else
            System.out.println("No message found to be sent");
    }

    public void sendMessageToServer(SendMessage sendMessage) throws UnknownHostException {
        try {
            Socket s = new Socket(hostName, Integer.parseInt(severPort));

            DataInputStream dataInputStream = new DataInputStream(s.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(s.getOutputStream());

            dataOutputStream.writeUTF(sendMessage.getSenderUserId());
            dataOutputStream.writeUTF(sendMessage.getMessageType());
            long timestamp = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
            dataOutputStream.writeLong(timestamp);
            dataOutputStream.writeInt(sendMessage.getRecipientUserId().length);
            dataOutputStream.write(sendMessage.getRecipientUserId());
            dataOutputStream.writeInt(sendMessage.getMessageBody().length);
            dataOutputStream.write(sendMessage.getMessageBody());
            addSignature(sendMessage, timestamp, dataOutputStream);
            CommonUtils.callCloseSocketAndStreams(dataInputStream, dataOutputStream, s);
        } catch (Exception e) {
            System.err.println("Cannot connect to server.");
            e.printStackTrace();
        }
    }

    private void addSignature(SendMessage sendMessage, long timestamp, DataOutputStream dataOutputStream) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        String contentToBeSigned = new String(sendMessage.getMessageBody()).concat(String.valueOf(timestamp));
        byte[] signature = CommonUtils.createSignature(contentToBeSigned, sendMessage.getSenderUserId());
        dataOutputStream.writeInt(signature.length);
        dataOutputStream.write(signature);
    }

    public void getMessageFromServer(SendMessage sendMessage) {
        try {
            Socket s = new Socket(hostName, Integer.parseInt(severPort));

            DataInputStream dataInputStream = new DataInputStream(s.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(s.getOutputStream());

            dataOutputStream.writeUTF(sendMessage.getSenderUserId());
            dataOutputStream.writeUTF(sendMessage.getMessageType());
            long timestamp = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
            dataOutputStream.writeLong(timestamp);

            long serverTimestamp = dataInputStream.readLong();
            int messageCount = dataInputStream.readInt();

            if (messageCount != 0){
                System.out.println("There are " + messageCount + " message(s) for you.");
                for (int i = 0; i < messageCount; i++) {
                    int messageLength = dataInputStream.readInt();
                    byte[] allData = new byte[messageLength];
                    dataInputStream.readFully(allData);

                    int signatureLength = dataInputStream.readInt();
                    byte[] signature = new byte[signatureLength];
                    dataInputStream.readFully(signature);

                    String contentToBeVerified = new String(allData).concat(String.valueOf(serverTimestamp));
                    if (CommonUtils.verifySignature(contentToBeVerified, "server", signature)) {
                        String serverResponse = RSAUtils.decryptMessageWithPrivate(allData, senderUserId);
                        System.out.println(serverResponse);
                    } else {
                        CommonUtils.callCloseSocketAndStreams(dataInputStream, dataOutputStream, s);
                        System.exit(1);
                    }
                }
            } else {
                System.out.println("There are 0 message(s) for you.");
            }

            CommonUtils.callCloseSocketAndStreams(dataInputStream, dataOutputStream, s);

        } catch (Exception e) {
            System.err.println("Cannot connect to server.");
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {

        if (args.length != 3) {
            System.err.println("Client UserId has not been passed");
            System.exit(-1);
        }

        String host = args[0];
        String port = args[1];
        String senderUserId = args[2];
        Client client = new Client(host, port, senderUserId);
        client.init();
    }
}
