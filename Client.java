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
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Scanner;

/**
 * @Citations Referenced official Java documents:
 * Socket Programming,
 * DataInputStream,
 * DataOutputStream,
 * Exceptions,
 * Javax,
 * Java Security exception library,
 * <br>
 * <br><b>Note:</b> All the imports are also included above the class
 */
public class Client {

    private String hostName;
    private String severPort;
    private String senderUserId;

    public Client(String hostName, String serverPort, String senderUserId) {
        this.hostName = hostName;
        this.severPort = serverPort;
        this.senderUserId = senderUserId;
    }

    public static void main(String[] args) {

        if (args.length != 3) {
            System.err.println("Usage: java Client localhost <<port>> <<userid>>");
            System.exit(-1);
        }

        String host = args[0];
        String port = args[1];
        String senderUserId = args[2];
        Client client = new Client(host, port, senderUserId);
        client.init();
    }

    private static void writeMessageToDataOutputStream(SendMessage sendMessage, DataOutputStream dataOutputStream, long timestamp) throws Exception {
        dataOutputStream.writeUTF(sendMessage.getSenderUserId());
        dataOutputStream.writeUTF(sendMessage.getMessageType());
        dataOutputStream.writeLong(timestamp);
        dataOutputStream.writeInt(sendMessage.getRecipientUserId().length);
        dataOutputStream.write(sendMessage.getRecipientUserId());
        dataOutputStream.writeInt(sendMessage.getMessageBody().length);
        dataOutputStream.write(sendMessage.getMessageBody());
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
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        });
        thread.start();
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

            if (messageCount != 0) {
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
                        String serverResponse = CommonUtils.decryptMessageWithPrivate(allData, senderUserId);
                        System.out.println(serverResponse);
                    } else {
                        CommonUtils.callCloseSocketAndStreams(dataInputStream, dataOutputStream, s);
                        System.exit(1);
                    }
                }
            } else {
                System.out.println("There are 0 message(s) for you.\n");
            }
            CommonUtils.callCloseSocketAndStreams(dataInputStream, dataOutputStream, s);
        } catch (Exception e) {
            System.err.println("Cannot connect to server.");
            e.printStackTrace();
        }
    }

    private void writeMessageDetailsAndSend(String actionSelection, Scanner scanner) throws IOException, InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (actionSelection.equalsIgnoreCase("y")) {
            System.out.println("Enter the recipient userid: ");
            String recipientUserId = scanner.nextLine();
            System.out.println("Enter your message: ");
            String message = scanner.nextLine();
            sendMessage(message, recipientUserId);
            System.exit(1);
        } else if (actionSelection.equalsIgnoreCase("n")) {
            System.exit(1);
        }
    }

    private void sendMessage(String message, String recipientUserId) {
        if (message != null) {
            try {
                byte[] encryptedRecipientUserIdBytes = CommonUtils.encryptMessageWithPublicKey(recipientUserId, "server");
                byte[] encryptedMessageBytes = CommonUtils.encryptMessageWithPublicKey(message, "server");
                sendMessageToServer(new SendMessage(senderUserId, encryptedRecipientUserIdBytes, encryptedMessageBytes, "send-message"));
            } catch (Exception e) {
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
            long timestamp = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
            writeMessageToDataOutputStream(sendMessage, dataOutputStream, timestamp);
            addSignature(sendMessage, timestamp, dataOutputStream);
            CommonUtils.callCloseSocketAndStreams(dataInputStream, dataOutputStream, s);
        } catch (Exception e) {
            System.err.println("Cannot connect to server.");
            e.printStackTrace();
        }
    }

    private void addSignature(SendMessage sendMessage, long timestamp, DataOutputStream dataOutputStream) throws Exception {
        String contentToBeSigned = new String(sendMessage.getMessageBody()).concat(String.valueOf(timestamp));
        byte[] signature = CommonUtils.createSignature(contentToBeSigned, sendMessage.getSenderUserId());
        dataOutputStream.writeInt(signature.length);
        dataOutputStream.write(signature);
    }


    //Private Inner class
    private class SendMessage {

        private String senderUserId;

        private byte[] recipientUserId;

        private byte[] messageBody;

        private String messageType;

        public SendMessage(String senderUserId, byte[] recipientUserId, byte[] messageBody, String messageType) {
            this.senderUserId = senderUserId;
            this.recipientUserId = recipientUserId;
            this.messageBody = messageBody;
            this.messageType = messageType;
        }

        public String getSenderUserId() {
            return senderUserId;
        }

        public byte[] getRecipientUserId() {
            return recipientUserId;
        }

        public byte[] getMessageBody() {
            return messageBody;
        }

        public String getMessageType() {
            return messageType;
        }

    }
}
