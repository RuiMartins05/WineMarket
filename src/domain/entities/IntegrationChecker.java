package domain.entities;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class IntegrationChecker {

	private SecretKeySpec keySpec;
	private File file;
	private SetHmacs currentHmac;

	public IntegrationChecker(String secretKey) {
		this.keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
		this.file = new File("./src/previousHmacs.txt");
		// this.previousHmac = loadPreviousHmacFromFile(file);
		this.currentHmac = new SetHmacs();
	}

	public void calculateHmac(String fileS) throws Exception {

		File f = new File(fileS);

		Mac hmac = Mac.getInstance("HmacSHA256");
		hmac.init(keySpec);

		try (BufferedInputStream b = new BufferedInputStream(new FileInputStream(f))) {
			byte[] buffer = new byte[1024];
			int r = b.read(buffer);
			while (r != -1) {
				hmac.update(buffer, 0, r);
				r = b.read(buffer);
			}
		}

		currentHmac.setHmacPerFile(fileS, hmac.doFinal());
	}

	public void writeHmacs() throws FileNotFoundException, IOException {

		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(this.file));
		oos.writeObject(this.currentHmac);
		oos.close();
	}

	public boolean verifyHmacs(List<String> fileNamesList)
			throws FileNotFoundException, IOException, ClassNotFoundException {

		ObjectInputStream oos = new ObjectInputStream(new FileInputStream(this.file));

		SetHmacs previousHmac = (SetHmacs) oos.readObject();
		oos.close();
		for (String fileName : fileNamesList) {
			byte[] currentFileHmac = this.currentHmac.getMapHmac(fileName);
			byte[] previousFileHmac = previousHmac.getMapHmac(fileName);

			if (!MessageDigest.isEqual(previousFileHmac, currentFileHmac)) {
				return false;
			}
		}
		return true;

	}
}