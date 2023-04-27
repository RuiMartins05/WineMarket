package domain.entities;

import java.io.Serializable;

public class Mensagem implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String sender;
	private String recipient;
	private byte[] message;

	public Mensagem(String sender, String recipient, byte[] message) {
		this.sender = sender;
		this.recipient = recipient;
		this.message = message;
	}

	public String getSender() {
		return sender;
	}

	public String getRecipient() {
		return recipient;
	}

	public byte[] getMessage() {
		return message;
	}

}