import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

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
 * <b>Note:</b> All the imports are also included
 */

class ServerClientHandler implements Runnable {

    public static final String SEND_MESSAGE_TYPE = "send-message";
    public static final String GET_MESSAGE_TYPE = "get-message";
    private final Socket socket;
    private Map<String, Queue<Server.ReceivedMessage>> messageQueue = null;

    public ServerClientHandler(Socket socket, Map<String, Queue<Server.ReceivedMessage>> messageQueue) {
        this.messageQueue = messageQueue;
        this.socket = socket;
    }

    public static byte[] createMessageBody(String message, String recipientUserId, String clientUserId, long timestamp) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Date: " + CommonUtils.writeFormattedTimestamp(timestamp) + "\n");
        try {
            stringBuilder.append("Message: " + message + "\n");
            return CommonUtils.encryptMessageWithPublicKey(stringBuilder.toString(), recipientUserId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void displayMessageSummaryToClient(Queue<Server.ReceivedMessage> receivedMessageQueue, DataOutputStream dos) throws IOException, NoSuchAlgorithmException {

        long timestamp = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
        dos.writeLong(timestamp);

        if (receivedMessageQueue != null && !receivedMessageQueue.isEmpty()) {
            System.out.println("delivering " + receivedMessageQueue.size() + " message(s)...\n");
            dos.writeInt(receivedMessageQueue.size());
            receivedMessageQueue.forEach(messageReceived -> {
                try {
                    dos.writeInt(messageReceived.getMessageBody().length);
                    dos.write(messageReceived.getMessageBody());
                    addSignature(messageReceived.getMessageBody(), timestamp, dos, "server");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        } else {
            System.out.println("no incoming message.\n");
            dos.writeInt(0);
        }
    }

    private static void addSignature(byte[] messageBody, long timestamp, DataOutputStream dataOutputStream, String senderUserId) throws Exception {
        String contentToBeSigned = new String(messageBody).concat(String.valueOf(timestamp));
        byte[] signature = CommonUtils.createSignature(contentToBeSigned, senderUserId);
        dataOutputStream.writeInt(signature.length);
        dataOutputStream.write(signature);
    }

    @Override
    public void run() {
        try {
            handleClient();
        } catch (Exception e) {
            e.getMessage();
        }
    }

    public void handleClient() throws RuntimeException, Exception {
        try {
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

            String clientUserId = dis.readUTF();
            System.out.println("login from user " + CommonUtils.generateMD5Hash(clientUserId));
            String messageType = dis.readUTF();
            long timeStamp = dis.readLong();
            if (messageType.equals(SEND_MESSAGE_TYPE)) {
                try {
                    System.out.println("incoming message from " + clientUserId);
                    System.out.println(CommonUtils.writeFormattedTimestamp(timeStamp));
                    processMessageFromClient(dis, clientUserId, dos, timeStamp);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            } else if (messageType.equals(GET_MESSAGE_TYPE)) {
                fetchClientMessage(dis, clientUserId, dos);
            }
        } catch (IOException | NoSuchAlgorithmException ioException) {
            ioException.printStackTrace();
        }
    }

    private void processMessageFromClient(DataInputStream dis, String clientUserId, DataOutputStream dos, long timeStamp) throws BadPaddingException, Exception {
        String message;
        int recipientUserIdLength = dis.readInt();
        byte[] recipientUserIdByte = new byte[recipientUserIdLength];
        dis.readFully(recipientUserIdByte);

        String recipientUserId = CommonUtils.decryptMessageWithPrivate(recipientUserIdByte, "server");
        System.out.println("recipient: " + recipientUserId);

        //Read Message Body
        int messageLength = dis.readInt();
        byte[] allEncryptedMessageData = new byte[messageLength];
        dis.readFully(allEncryptedMessageData);

        //Read Signature
        int signatureLength = dis.readInt();
        byte[] signature = new byte[signatureLength];
        dis.readFully(signature);

        try {
            String contentToBeVerified = new String(allEncryptedMessageData).concat(String.valueOf(timeStamp));
            if (CommonUtils.verifySignature(contentToBeVerified, clientUserId, signature)) {
                if (allEncryptedMessageData != null) {
                    message = CommonUtils.decryptMessageWithPrivate(allEncryptedMessageData, "server");
                    System.out.println("message: " + message + "\n");
                    byte[] messageBody = createMessageBody(message, recipientUserId, clientUserId, timeStamp);
                    Server.ReceivedMessage receivedMessage = new Server.ReceivedMessage(clientUserId, LocalDateTime.now(), messageBody);
                    dos.writeUTF("Server Received " + message);
                    addMessageToQueue(recipientUserId, receivedMessage);
                }
            } else {
                CommonUtils.callCloseSocketAndStreams(dis, dos, socket);
            }
        } catch (IOException e) {
            System.err.println("Client closed its connection.");
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 InvalidKeySpecException | InvalidKeyException | BadPaddingException e) {
            throw new RuntimeException(e);
        } finally {
            CommonUtils.callCloseSocketAndStreams(dis, dos, socket);
        }
    }

    private synchronized void addMessageToQueue(String recipientUserId, Server.ReceivedMessage receivedMessage) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        recipientUserId = CommonUtils.generateMD5Hash(recipientUserId);
        messageQueue.putIfAbsent(recipientUserId, new ConcurrentLinkedQueue<>());
        messageQueue.get(recipientUserId).add(receivedMessage);
    }

    private void fetchClientMessage(DataInputStream dis, String clientUserId, DataOutputStream dos) throws Exception {
        try {
            Queue<Server.ReceivedMessage> receivedMessageQueue = getClientMessagesQueue(clientUserId);
            displayMessageSummaryToClient(receivedMessageQueue, dos);
        } catch (RuntimeException e) {
            throw new RuntimeException(e);
        } finally {
            CommonUtils.callCloseSocketAndStreams(dis, dos, socket);
        }
    }

    public synchronized Queue<Server.ReceivedMessage> getClientMessagesQueue(String clientUserId) {
        clientUserId = CommonUtils.generateMD5Hash(clientUserId);
        Queue<Server.ReceivedMessage> receivedMessages = messageQueue.getOrDefault(clientUserId, new ConcurrentLinkedQueue<>());
        messageQueue.remove(clientUserId);
        return receivedMessages;
    }

}
