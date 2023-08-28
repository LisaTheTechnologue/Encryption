package main.java.org.simple.mail.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.signature.forward.util.SignatureUtil;

import main.java.org.rsa.echo.util.RSAUtil;
import main.java.org.secure.echo.util.AESUtil;
import main.java.org.simple.mail.util.Command;
import main.java.org.simple.mail.util.Mail;
import main.java.org.simple.mail.util.Request;
import main.java.org.simple.mail.util.Response;
import main.java.org.simple.mail.util.TcpChannel;

public class UserProcessor {
	private Socket socket;
	private Request request;
	private Response response;
	private TcpChannel channel;
	private boolean debug = false;

	public UserProcessor(Socket sock) {
		this.socket = sock;
		try {
			channel = new TcpChannel(socket);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public int process() throws IOException {
		String command = request.getCommand();
		channel.sendRequest(request);
		response = channel.receiveResponse();
		if (response != null) {
			handleResponse(command);
			return 0;
		} else
			return -1;
	}

	public void setResponse(Response res) {
		this.response = res;
	}

	public void setRequest(Request req) {
		this.request = req;
	}

	private void handleResponse(String command) throws IOException {
		System.out.println("Receive: " + response.craftToString());

		String returnCode = response.getCode();
		if (returnCode.compareTo(Response.SUCCESS) == 0) {
			if (command.compareToIgnoreCase(Command.DATA) == 0)
				doDataResponse();
			else if (command.compareToIgnoreCase(Command.LIST) == 0)
				doListResponse();
			else if (command.compareToIgnoreCase(Command.RETRIEVE) == 0)
				doRetrieveResponse();
		}
	}

	private void doDataResponse() throws IOException {
		System.out.println("Send: ");

		String line;// , messageOriginal = null, messageEncrypted = null;
		StringBuilder messageOriginal = new StringBuilder();
		String messageEncrypted;
		BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
		do {
			line = user.readLine();
			if (line.compareTo(Mail.END_MAIL) != 0) {
				messageOriginal.append(line + "\n");
			}
		} while (line.compareTo(Mail.END_MAIL) != 0);

		messageEncrypted = encryptMail(messageOriginal.toString());

		channel.sendRequest(new Request(messageEncrypted));
		channel.sendRequest(new Request("."));

		response = channel.receiveResponse();
		System.out.println(response.craftToString());
	}

	private String encryptMail(String mail) {
		String messageEncrypted = mail;

		StringBuilder encrypt = new StringBuilder();
		// TODO AES
		AESUtil aesCryptor = new AESUtil();
		SecretKey key;
		try {
			key = aesCryptor.getSecretKey();
//			System.out.println(key);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | UnsupportedEncodingException e) {
			e.printStackTrace();
			key = null;
		}

		if (key != null) {
			try {
				messageEncrypted = aesCryptor.encryptString(key, mail);
			} catch (UnsupportedEncodingException | GeneralSecurityException e) {
				e.printStackTrace();
				return "";
			}
		} else {
			return "";
		}

		// TODO RSA
		SignatureUtil signOperator = new SignatureUtil();
		RSAUtil rsaCryptor = new RSAUtil();
		RSAKeyParameters recipientPublicKey;
		String recipientPublicKeyFile;

		try (BufferedReader user = new BufferedReader(new InputStreamReader(System.in))) {
			System.out.print("Path to recipient's public key: ");
			if (debug) {
				recipientPublicKeyFile = "alicepub.pem";
			} else {
				recipientPublicKeyFile = user.readLine();
			}
			recipientPublicKey = rsaCryptor.getPublicKey(recipientPublicKeyFile);

			// Import client private key file
			RSAKeyParameters senderPrivateKey = null;
			String senderPrivateKeyFile, keyPassword;
			System.out.print("Path to your private key: ");
//			senderPrivateKeyFile = user.readLine();
			if (debug) {
				senderPrivateKeyFile = "tungpriv.pem";
			} else {
				senderPrivateKeyFile = user.readLine();
			}

			System.out.print("Password for using private key: ");
			if (debug) {
				keyPassword = "1234";
			} else {
				keyPassword = user.readLine();
			}

			try {
				senderPrivateKey = signOperator.getPrivateKey(senderPrivateKeyFile, keyPassword);
			} catch (OperatorCreationException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				return "";
			} catch (PKCSException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				return "";
			}
			String signature = null;
			try {
				signature = signOperator.signString(senderPrivateKey, messageEncrypted);
			} catch (DataLengthException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "";
			} catch (CryptoException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "";
			}

			String keyEncrypted = null;
			try {
				String encodedString = aesCryptor.convertSecretKeyToString(key);
				keyEncrypted = rsaCryptor.encryptString(recipientPublicKey, encodedString);
//				System.out.println(keyEncrypted);
			} catch (InvalidCipherTextException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "";
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			encrypt.append(Mail.SIG_HEADER + signature);
			encrypt.append("\n");
			encrypt.append(Mail.KEY + keyEncrypted);
			encrypt.append("\n");
			encrypt.append(Mail.BODY + messageEncrypted);
			encrypt.append("\n");

			return encrypt.toString();
		} catch (IOException e) {
			e.printStackTrace();
			return "";
		}
	}

	private void doListResponse() throws IOException {
		StringBuilder builder = new StringBuilder();
		int numberOfMail = Integer.parseInt(response.getNotice());
		for (int i = 0; i < numberOfMail; i++)
			builder.append(channel.receiveLine());
		System.out.println(builder.toString());
	}

	private void doRetrieveResponse() throws IOException {
		StringBuilder builder = new StringBuilder();
		String line;
		String mail = null;
		String encryptedMail = "";
		int leftBytes = Integer.parseInt(response.getNotice()) + 1;
		while (leftBytes > 0) {
			line = channel.receiveLine();
			if (line.startsWith(Mail.SIG_HEADER) || line.startsWith(Mail.KEY) || line.startsWith(Mail.BODY)) {
				encryptedMail += line;
				encryptedMail += "\n";
				if (line.startsWith(Mail.BODY)) {
					mail = decryptMessage(encryptedMail);
					if (mail.equals("")) {
						builder.setLength(0);
						break;
					}
					builder.append(mail);
					break;
				}
			} else {
				builder.append(line);
			}
			leftBytes = leftBytes - line.length();
		}
		System.out.println(builder.toString());
	}

	public String decryptMessage(String encryptedMail) {
		// Import server's private key
		RSAUtil rsaCryptor = new RSAUtil();
		RSAKeyParameters recipientPrivateKey;
		String senderPublicKeyFile, recipientPrivateKeyFile, keyPassword;
		SignatureUtil verifyOperator = new SignatureUtil();
		try (BufferedReader user = new BufferedReader(new InputStreamReader(System.in))) {

			// Import server's private key
			RSAKeyParameters senderPublicKey;
			System.out.print("Path to sender's public key: ");
			if (debug) {
				senderPublicKeyFile = "tungpub.pem";
			} else {
				senderPublicKeyFile = user.readLine();
			}
			try {
				senderPublicKey = rsaCryptor.getPublicKey(senderPublicKeyFile);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "";
			}

			System.out.print("Path to your private key: ");
			if (debug) {
				recipientPrivateKeyFile = "alicepriv.pem";
			} else {
				recipientPrivateKeyFile = user.readLine();
			}

			System.out.print("Password for using private key: ");
			if (debug) {
				keyPassword = "1234";
			} else {
				keyPassword = user.readLine();
			}

			try {
				recipientPrivateKey = rsaCryptor.getPrivateKey(recipientPrivateKeyFile, keyPassword);
			} catch (OperatorCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "";
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "";
			} catch (PKCSException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "";
			}

			String signature = new String(), key = new String(), body = new String();
			String message[] = encryptedMail.split("\\r?\\n");
			int i;
			for (i = 0; i < message.length; i++) {

				if (message[i].startsWith(Mail.SIG_HEADER) == true)
					signature = message[i].substring(Mail.SIG_HEADER.length());
				else if (message[i].startsWith(Mail.KEY) == true) {
					key = message[i].substring(Mail.KEY.length());
				} else if (message[i].startsWith(Mail.BODY) == true)
					body = message[i].substring(Mail.BODY.length());
			}

			boolean isSignatureValid = verifySignature(verifyOperator, senderPublicKey, body, signature);
			if (!isSignatureValid) {
				return "";
			}

			try {
				key = rsaCryptor.decryptString(recipientPrivateKey, key);
				if (debug) {
					System.out.println(key);
				}
			} catch (InvalidCipherTextException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "";
			}
			if (key.equals("")) {
				return "";
			}

			body = decryptBody(key, body);
			return body;

		} catch (IOException e) {
			e.printStackTrace();
		}
		return "";
	}

	private boolean verifySignature(SignatureUtil verifyOperator, RSAKeyParameters senderPublicKey, String body,
			String signature) {
		try {
			if (verifyOperator.verifyString(senderPublicKey, body, signature)) {
				if (debug) {
					System.out.println("Message is authentic");
				}
				return true;
			} else {
				System.out.println("Message is not authentic");
				return false;
			}
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
	}

	private String decryptBody(String key, String body) {
		AESUtil aesCryptor = new AESUtil();
		SecretKey secretKey;
		secretKey = aesCryptor.convertStringToSecretKeyto(key);
		try {
			body = aesCryptor.decryptString(secretKey, body);
			if (debug) {
				System.out.println(body);
			}
			return body;
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "";
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "";
		}
	}
}
