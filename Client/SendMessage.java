public class SendMessage {

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

    public void setSenderUserId(String senderUserId) {
        this.senderUserId = senderUserId;
    }

    public byte[] getRecipientUserId() {
        return recipientUserId;
    }

    public void setRecipientUserId(byte[] recipientUserId) {
        this.recipientUserId = recipientUserId;
    }

    public byte[] getMessageBody() {
        return messageBody;
    }

    public void setMessageBody(byte[] messageBody) {
        this.messageBody = messageBody;
    }

    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }
}
