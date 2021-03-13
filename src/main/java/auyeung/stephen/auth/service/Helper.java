package auyeung.stephen.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Helper {

	private static SecureRandom random = new SecureRandom(); 
	public static byte[] getNewSalt() {		
	    byte[] salt = new byte[16];
	    random.nextBytes(salt);
	    return salt;
	}

	private static StringBuilder sb = new StringBuilder();
	public static String hash(String plainText, byte[] salt) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");		
        md.update(salt);
        byte[] hashedPassword = md.digest(plainText.getBytes(StandardCharsets.UTF_8));
        sb.setLength(0);
        for (byte b : hashedPassword) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
	}
	
	public static String normalizeUserName(String userName) {
		if(userName == null) {
			return "";
		}
		return userName.toLowerCase();
	}
	
	public static String AESEncrypt(String message, String secret) throws Exception {
		
		byte[] key = secret.getBytes(StandardCharsets.UTF_8);
		byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

		Cipher c = Cipher.getInstance("AES");
		SecretKeySpec k = new SecretKeySpec(key, "AES");
		c.init(Cipher.ENCRYPT_MODE, k);
		byte[] encryptedData = c.doFinal(messageBytes);
		return encodeHexString(encryptedData);		
	}
	
	public static String AESDecrypt(String message, String secret) throws Exception {
	
		byte[] key = secret.getBytes(StandardCharsets.UTF_8); 	
		byte[] encryptedData = decodeHexString(message);

		Cipher c = Cipher.getInstance("AES");
		SecretKeySpec k =
		  new SecretKeySpec(key, "AES");
		c.init(Cipher.DECRYPT_MODE, k);
		byte[] data = c.doFinal(encryptedData);
		return new String(data, StandardCharsets.UTF_8);
	}
	
	public static String byteToHex(byte num) {
	    char[] hexDigits = new char[2];
	    hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
	    hexDigits[1] = Character.forDigit((num & 0xF), 16);
	    return new String(hexDigits);
	}
	
	public static String encodeHexString(byte[] byteArray) {
	    StringBuffer hexStringBuffer = new StringBuffer();
	    for (int i = 0; i < byteArray.length; i++) {
	        hexStringBuffer.append(byteToHex(byteArray[i]));
	    }
	    return hexStringBuffer.toString();
	}
	
	public static byte[] decodeHexString(String hexString) {
	    if (hexString.length() % 2 == 1) {
	        throw new IllegalArgumentException(
	          "Invalid hexadecimal String supplied.");
	    }
	    
	    byte[] bytes = new byte[hexString.length() / 2];
	    for (int i = 0; i < hexString.length(); i += 2) {
	        bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
	    }
	    return bytes;
	}
	
	public static byte hexToByte(String hexString) {
	    int firstDigit = toDigit(hexString.charAt(0));
	    int secondDigit = toDigit(hexString.charAt(1));
	    return (byte) ((firstDigit << 4) + secondDigit);
	}
	
	private static int toDigit(char hexChar) {
	    int digit = Character.digit(hexChar, 16);
	    if(digit == -1) {
	        throw new IllegalArgumentException(
	          "Invalid Hexadecimal Character: "+ hexChar);
	    }
	    return digit;
	}
}
