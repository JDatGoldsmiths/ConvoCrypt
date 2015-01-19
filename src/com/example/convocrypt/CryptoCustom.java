package com.example.convocrypt;
import javax.crypto.*;
import java.security.*;
import java.lang.*;

import org.apache.commons.codec.binary.Hex;


public class CryptoCustom {

	public static KeyPairGenerator kpg;
	
	public static KeyPair keypair;
	public static Key publicKey;
	public static Key privateKey;

	public static Cipher cipher;
	
	CryptoCustom() throws Exception{

		kpg = KeyPairGenerator.getInstance("RSA");
		keypair = kpg.genKeyPair();
		publicKey = keypair.getPublic();
		privateKey = keypair.getPrivate();
		kpg.initialize(4000);
		
		cipher = Cipher.getInstance("RSA");

		System.out.println("\n Private Key: " + privateKey);

		System.out.println();

		System.out.println(publicKey);
		
		
		System.out.println();
		
		
		String message = "hello this is an example of an ecrypted message";
		
		System.out.println(" --- ");
		
		
		System.out.println(message);
		
		
		String enc = encrypt(message);
		
		System.out.println(enc);
		
		
		
		
		String dec =  decrypt(enc);
		System.out.println(" --- ");
		System.out.println(dec);

		

/*

Bluetooth could be more secure than the internet?



File transfers that you typically do when you tap each others phone and use NFC actually just use bluetooth so technically the file size would be unlimited. The NFC is only used to negotiate a connection. (Kind of like showing your ID card when you go to work instead of signing in at the front desk as a guest)

NFC tags on the other hand cannot store very much data. Often only enough for a small string of characters. In this sense, the size limit is very small.
*/

	}
	
	public static String encrypt(String plaintext) throws Exception{
		cipher.init(Cipher.ENCRYPT_MODE, keypair.getPublic());
		byte[] bytes = plaintext.getBytes("UTF-8");

		byte[] encrypted = blockCipher(bytes,Cipher.ENCRYPT_MODE);

		char[] encryptedTranspherable = Hex.encodeHex(encrypted);
		return new String(encryptedTranspherable);
	}
	
	public static String decrypt(String encrypted) throws Exception{
		cipher.init(Cipher.DECRYPT_MODE, keypair.getPrivate());
		byte[] bts = Hex.decodeHex(encrypted.toCharArray());

		byte[] decrypted = blockCipher(bts,Cipher.DECRYPT_MODE);

		return new String(decrypted,"UTF-8");
	}

	public static byte[] blockCipher(byte[] bytes, int mode) throws IllegalBlockSizeException, BadPaddingException{
		// string initialize 2 buffers.
		// scrambled will hold intermediate results
		byte[] scrambled = new byte[0];

		// toReturn will hold the total result
		byte[] toReturn = new byte[0];
		// if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
		int length = (mode == Cipher.ENCRYPT_MODE)? 100 : 128;

		// another buffer. this one will hold the bytes that have to be modified in this step
		byte[] buffer = new byte[length];

		for (int i=0; i< bytes.length; i++){

			// if we filled our buffer array we have our block ready for de- or encryption
			if ((i > 0) && (i % length == 0)){
				//execute the operation
				scrambled = cipher.doFinal(buffer);
				// add the result to our total result.
				toReturn = append(toReturn,scrambled);
				// here we calculate the length of the next buffer required
				int newlength = length;

				// if newlength would be longer than remaining bytes in the bytes array we shorten it.
				if (i + length > bytes.length) {
					 newlength = bytes.length - i;
				}
				// clean the buffer array
				buffer = new byte[newlength];
			}
			// copy byte into our buffer.
			buffer[i%length] = bytes[i];
		}

		// this step is needed if we had a trailing buffer. should only happen when encrypting.
		// example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
		scrambled = cipher.doFinal(buffer);

		// final step before we can return the modified data.
		toReturn = append(toReturn,scrambled);

		return toReturn;
	}
	
	
	public static byte[] append(byte[] prefix, byte[] suffix){
		byte[] toReturn = new byte[prefix.length + suffix.length];
		for (int i=0; i< prefix.length; i++){
			toReturn[i] = prefix[i];
		}
		for (int i=0; i< suffix.length; i++){
			toReturn[i+prefix.length] = suffix[i];
		}
		return toReturn;
	}

	
}
