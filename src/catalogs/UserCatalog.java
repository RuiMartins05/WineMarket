package catalogs;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import domain.User;

public class UserCatalog {

	private static UserCatalog instance;
	private ArrayList<User> userCatalog;

	private UserCatalog() {
		userCatalog = new ArrayList<User>();
	}

	public static UserCatalog getUserCatalog() {
		if (instance == null)
			instance = new UserCatalog();

		return instance;
	}

	public synchronized User getUserByID(String id) {

		for (User w : userCatalog) {
			if (w.getID().equals(id))
				return w;
		}

		return null;

	}

	public synchronized int watchWallet(User u) {
		return u.getBalance();
	}

	public synchronized void add(User user) {
		userCatalog.add(user);
	}

	public synchronized Boolean exists(String clientID) {
		return instance.getUserByID(clientID) != null;
	}

	public synchronized int getSize() {
		return userCatalog.size();
	}
	
	public static void decryptUsers(String inputFile, String outputFile, String password)
	        throws GeneralSecurityException, IOException {

	    FileInputStream fis = new FileInputStream(inputFile);
	    FileOutputStream fos = new FileOutputStream(outputFile);

	    byte[] salt = new byte[8];
	    fis.read(salt);

	    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); 
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

	    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
	    SecretKey key = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES");

	    byte[] iv = new byte[16];
	    fis.read(iv);

	    AlgorithmParameters params = AlgorithmParameters.getInstance("AES");
	    params.init(new IvParameterSpec(iv));
	    cipher.init(Cipher.DECRYPT_MODE, key, params);

	    // Decifra o usersCatalog
	    byte[] in = new byte[64]; 
	    int read;
	    while ((read = fis.read(in)) != -1) {
	        byte[] output = cipher.update(in, 0, read);
	        if (output != null) {
	            fos.write(output);
	        }
	    }
	    byte[] output = cipher.doFinal();
	    if (output != null) {
	        fos.write(output);
	    }

	    fis.close();
	    fos.flush();
	    fos.close();
	}



}