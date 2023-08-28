package main.java.org.simple.mail.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Mail {
	public final static String FROM = "FROM: "; 
	public final static String TO = "TO: ";
	public final static String DATE = "DATE: ";
	public final static String END_MAIL = ".";
	public static final String SIG_HEADER = "SIG:";
	public static final String KEY = "KEY:";
	public static final String BODY = "BODY:";
	
	private String sender;
	private String recipient;
	private Date receivedTime;
	private String body;
	private String keyAES;
	private String keyRSA;

	public String craftToString(){
		StringBuilder builder = new StringBuilder();
		DateFormat dateFormat = new SimpleDateFormat("yyyy-mm-dd");  
		
		builder.append(FROM + sender + "\n");
		builder.append(TO + recipient + "\n");
		builder.append(DATE + dateFormat.format(receivedTime) + "\n");
		builder.append(body);
		
		return builder.toString();
	}
	
	
	public void setSender(String sender){
		this.sender = sender.toLowerCase();
	}
	
	public void setRecipient(String recipient){
		this.recipient = recipient.toLowerCase();
	}
	
	public void setBody(String body){
		this.body = body;
	}
	
	public void setTime(Date time){
		this.receivedTime = time;

	}
	
	public String getSender(){
		return this.sender;
	}
	
	public String getRecipient(){
		return this.recipient;
	}
	
	public String getBody(){
		return this.body;
	}
	
	public Date getReceivedTime(){
		return this.receivedTime;
	}


	public String getKeyAES() {
		return keyAES;
	}


	public void setKeyAES(String keyAES) {
		this.keyAES = keyAES;
	}


	public String getKeyRSA() {
		return keyRSA;
	}


	public void setKeyRSA(String keyRSA) {
		this.keyRSA = keyRSA;
	}
	
}
