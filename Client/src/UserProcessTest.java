import static org.junit.Assert.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import main.java.org.rsa.echo.util.RSAUtil;
import main.java.org.secure.echo.util.AESUtil;

public class UserProcessTest {

	@Test
	public void testAESRSA() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidCipherTextException, OperatorCreationException, IOException, PKCSException {
		// encrypt
		AESUtil aesCryptor = new AESUtil();
		RSAUtil rsaCryptor = new RSAUtil();
		
		SecretKey key;
		String keyPassword, aesKey, keyEncrypted;
		keyPassword = "1234";
		aesKey = "1234";
		// encrypt
		RSAKeyParameters recipientPublicKey;
		String recipientPublicKeyFile = "alicepub.pem";
		recipientPublicKey = rsaCryptor.getPublicKey(recipientPublicKeyFile);
		
		key = aesCryptor.getSecretKey(aesKey);
		System.out.println(key);		
		
		String encodedString = convertSecretKeyToString(key);
		System.out.println(encodedString);
		keyEncrypted = rsaCryptor.encryptString(recipientPublicKey, encodedString);
		
		// decrypt
		RSAKeyParameters recipientPrivateKey;
		String recipientPrivateKeyFile = "alicepriv.pem";
		recipientPrivateKey = rsaCryptor.getPrivateKey(recipientPrivateKeyFile, keyPassword);

		String keyDecryptedString = rsaCryptor.decryptString(recipientPrivateKey, keyEncrypted);
		SecretKey decodeKey = convertStringToSecretKeyto(keyDecryptedString);
		System.out.println(decodeKey);	
		assertEquals(key, decodeKey);
	}
	
	@Test
	public void testConversion() throws NoSuchAlgorithmException, InvalidKeySpecException {
		AESUtil aesCryptor = new AESUtil();
		SecretKey encodedKey = aesCryptor.getSecretKey("Baeldung@2021");
		System.out.println(encodedKey);
		
		String encodedString = convertSecretKeyToString(encodedKey);
		System.out.println(encodedString);
		
		SecretKey decodeKey = convertStringToSecretKeyto(encodedString);
		System.out.println(decodeKey);
		
		assertEquals(encodedKey, decodeKey);
	}
	
	public String convertSecretKeyToString(SecretKey secretKey) throws NoSuchAlgorithmException {
	    byte[] rawData = secretKey.getEncoded();
	    String encodedKey = Base64.toBase64String(rawData);
	    return encodedKey;
	}
	public SecretKey convertStringToSecretKeyto(String encodedKey) {
	    byte[] decodedKey = Base64.decode(encodedKey);
	    SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
	    return originalKey;
	}
}
