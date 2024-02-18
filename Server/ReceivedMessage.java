import java.time.LocalDateTime;

public class ReceivedMessage {
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
