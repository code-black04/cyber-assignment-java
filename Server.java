import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.time.LocalDateTime;

public class Server {

    private String serverPort;
    private Map<String, Queue<ReceivedMessage>> messageQueue;

    public Server(String serverPort) {
        this.messageQueue = new HashMap<>();
        this.serverPort = serverPort;
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java Server <<port>>");
            System.exit(-1);
        }

        String port = args[0];
        System.out.println("Starting server at port: " + port + "\n");
        try {
            new Server(port).startServer();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public void startServer() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(Integer.parseInt(serverPort))) {
            System.out.println("Waiting incoming connection requests: \n");
            createClientHandlerForEachClient(serverSocket);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void createClientHandlerForEachClient(ServerSocket serverSocket) throws IOException {
        while (true) {
            Socket socket = serverSocket.accept(); // Accept incoming connections
            Thread thread = new Thread(new ServerClientHandler(socket, messageQueue));
            thread.start();
        }
    }

    public static class ReceivedMessage {
        private String senderUserId;

        private LocalDateTime dateTime;

        private byte[] messageBody;

        public ReceivedMessage(String senderUserId, LocalDateTime dateTime, byte[] messageBody) {
            this.senderUserId = senderUserId;
            this.dateTime = dateTime;
            this.messageBody = messageBody;
        }

        public String getSenderUserId() {
            return senderUserId;
        }

        public void setSenderUserId(String senderUserId) {
            this.senderUserId = senderUserId;
        }

        public LocalDateTime getDateTime() {
            return dateTime;
        }

        public void setDateTime(LocalDateTime dateTime) {
            this.dateTime = dateTime;
        }

        public byte[] getMessageBody() {
            return messageBody;
        }

        public void setMessageBody(byte[] messageBody) {
            this.messageBody = messageBody;
        }
    }
}
