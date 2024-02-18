import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

class ServerClientHandler implements Runnable {

    public static final String SEND_MESSAGE_TYPE = "send-message";
    public static final String GET_MESSAGE_TYPE = "get-message";
    private final Socket socket;
    private Map<String, Queue<ReceivedMessage>> messageQueue = null;

    public ServerClientHandler(Socket socket, Map<String, Queue<ReceivedMessage>> messageQueue) {
        this.messageQueue = messageQueue ;
        this.socket = socket;
    }


    @Override
    public void run() {
        handleClient();
    }

    public void handleClient() throws RuntimeException{
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
                    System.out.println(LocalDateTime.now());
                    processMessageFromClient(dis, clientUserId, dos, timeStamp);
                } catch (NoSuchPaddingException | InvalidKeyException | BadPaddingException | InvalidKeySpecException |
                         NoSuchAlgorithmException | IllegalBlockSizeException | SignatureException e) {
                    throw new RuntimeException(e);
                }
            } else if (messageType.equals(GET_MESSAGE_TYPE)) {
                fetchClientMessage(dis, clientUserId, dos);
            }
        } catch (IOException | NoSuchAlgorithmException ioException) {
            ioException.printStackTrace();
        }
    }

    private void processMessageFromClient(DataInputStream dis, String clientUserId, DataOutputStream dos, long timeStamp) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, BadPaddingException, InvalidKeyException {
        String message;
        int recipientUserIdLength = dis.readInt();
        byte[] recipientUserIdByte = new byte[recipientUserIdLength];
        dis.readFully(recipientUserIdByte);

        String recipientUserId = RSAUtils.decryptMessageWithPrivate(recipientUserIdByte, "server");
        System.out.println("recipient: " + recipientUserId);
        //messageBody
        int messageLength = dis.readInt();
        byte[] allEncryptedMessageData = new byte[messageLength];
        dis.readFully(allEncryptedMessageData);

        int signatureLength = dis.readInt();
        byte[] signature = new byte[signatureLength];
        dis.readFully(signature);

        try {
            String contentToBeVerified = new String(allEncryptedMessageData).concat(String.valueOf(timeStamp));
            if (CommonUtils.verifySignature(contentToBeVerified, clientUserId, signature)) {
                if (allEncryptedMessageData != null) {
                    message = RSAUtils.decryptMessageWithPrivate(allEncryptedMessageData, "server");
                    System.out.println("message: " + message);
                    byte[] messageBody = createMessageBody(message, recipientUserId, clientUserId);
                    ReceivedMessage receivedMessage = new ReceivedMessage(clientUserId, LocalDateTime.now(), messageBody);
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

    public static byte[] createMessageBody(String message, String recipientUserId, String clientUserId) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Date: " + LocalDateTime.now() + "\n");
        try {
            stringBuilder.append("Message: " + message + "\n\n");
            return RSAUtils.encryptMessageWithPublicKey(stringBuilder.toString(), recipientUserId);
        } catch (IOException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException |
                 NoSuchPaddingException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private synchronized void addMessageToQueue(String recipientUserId, ReceivedMessage receivedMessage) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        recipientUserId = CommonUtils.generateMD5Hash(recipientUserId);
        messageQueue.putIfAbsent(recipientUserId, new ConcurrentLinkedQueue<>());
        messageQueue.get(recipientUserId).add(receivedMessage);
    }

    private void fetchClientMessage(DataInputStream dis, String clientUserId, DataOutputStream dos) throws IOException, NoSuchAlgorithmException{
        try {
            Queue<ReceivedMessage> receivedMessageQueue = getClientMessagesQueue(clientUserId);
            displayMessageSummaryToClient(receivedMessageQueue, dos);
        } catch (RuntimeException e) {
            throw new RuntimeException(e);
        } finally {
            socket.close();
            dis.close();
            dos.close();
        }
    }

    private static void displayMessageSummaryToClient(Queue<ReceivedMessage> receivedMessageQueue, DataOutputStream dos) throws IOException, NoSuchAlgorithmException{

        long timestamp = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
        dos.writeLong(timestamp);

        if (receivedMessageQueue != null && !receivedMessageQueue.isEmpty()) {
            System.out.println("delivering " + receivedMessageQueue.size() + " message(s)...");
            dos.writeInt(receivedMessageQueue.size());
            //stringBuilder.append("There are " + receivedMessageQueue.size() + " message(s) for you.\n");
            receivedMessageQueue.forEach(messageReceived -> {
                try {
                    dos.writeInt(messageReceived.getMessageBody().length);
                    dos.write(messageReceived.getMessageBody());
                    addSignature(messageReceived.getMessageBody(), timestamp, dos, "server");
                } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
                    throw new RuntimeException(e);
                }
            });
        } else {
            System.out.println("no incoming message.");
            dos.writeInt(0);
        }
    }

    private static void addSignature(byte[] messageBody, long timestamp, DataOutputStream dataOutputStream, String senderUserId) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        String contentToBeSigned = new String(messageBody).concat(String.valueOf(timestamp));
        byte[] signature = CommonUtils.createSignature(contentToBeSigned, senderUserId);
        dataOutputStream.writeInt(signature.length);
        dataOutputStream.write(signature);
    }

    public synchronized Queue<ReceivedMessage> getClientMessagesQueue(String clientUserId) {
        clientUserId = CommonUtils.generateMD5Hash(clientUserId);
        Queue<ReceivedMessage> receivedMessages = messageQueue.getOrDefault(clientUserId, new ConcurrentLinkedQueue<>());
        messageQueue.remove(clientUserId);
        return receivedMessages;
    }
}
