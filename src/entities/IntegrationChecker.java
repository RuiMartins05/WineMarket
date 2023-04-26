package entities;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class IntegrationChecker {

	private SecretKeySpec keySpec;
	private byte[] previousHmac;
	private File file;

	public IntegrationChecker(String secretKey) {
		this.keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
		this.file = new File("./src/previousHmacs.txt");
		this.previousHmac = loadPreviousHmacFromFile(file);
	}

	public boolean isPreviousHmacNull(File fileS, File fileS2, File fileS3, File fileS4) throws Exception {

		if (previousHmac == null) { // previous = null (nunca foi analisado antes)

			// guarda o  hmac do primeiro ficheiro
			byte[] hmacP = calculateHmac(fileS);
			this.previousHmac = Arrays.copyOfRange(hmacP, 0, 32);

			try (FileOutputStream fos = new FileOutputStream(this.file)) {

				//escreve todos os hmacs no ficheiro
				for (File file : Arrays.asList(fileS, fileS2, fileS3, fileS4)) {
					byte[] hmac = calculateHmac(file);
					fos.write(hmac);
					fos.write(System.lineSeparator().getBytes(StandardCharsets.UTF_8));
				}
			}

			return true;
		}
		return false;
	}

	public boolean beforeVsNowIntegrity(File fileS) throws Exception {
		byte[] currentHmac = calculateHmac(fileS);

		if (MessageDigest.isEqual(previousHmac, currentHmac)) {
			this.previousHmac = loadPreviousHmacFromFile(file);
			return true;

		} else {
			this.previousHmac = currentHmac;
			savePreviousHmacToFile(file, this.previousHmac);
			return false;
		}
	}

	private byte[] calculateHmac(File fileS) throws Exception {
		Mac hmac = Mac.getInstance("HmacSHA256");
		hmac.init(keySpec);

		try (BufferedInputStream b = new BufferedInputStream(new FileInputStream(fileS))) {
			byte[] buffer = new byte[1024];
			int r = b.read(buffer);
			while (r != -1) {
				hmac.update(buffer, 0, r);
				r = b.read(buffer);
			}
		}

		return hmac.doFinal();
	}

	private byte[] loadPreviousHmacFromFile(File fileS) {

		byte[] hmac = null;
		try (BufferedReader reader = new BufferedReader(new FileReader(fileS))) {

			String firstLine = reader.readLine();

			if (firstLine == null) { // 1ª iteracao
				return null;
			}

			hmac = firstLine.getBytes(StandardCharsets.UTF_8);

			// guarda tudo o resto num stringbuilder
			StringBuilder content = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				content.append(line).append(System.lineSeparator());
			}

			// apaga o conteudo do ficheiro
			FileWriter arquivo = new FileWriter(fileS, false);

			// coloca de volta a info, mas o primeiro hmac passa para ultimo
			FileWriter writer = new FileWriter(fileS, true);
			writer.write(content.append(firstLine).toString() + System.lineSeparator());
			writer.close();

			this.previousHmac = hmac;

			return hmac;

		} catch (IOException e) {
			e.getMessage();
			return null;
		}
	}


	private void savePreviousHmacToFile(File fileS, byte[] newHmac) {

		try (BufferedReader reader = new BufferedReader(new FileReader(fileS))) {

			// só para dar skip
			reader.readLine();

			// guarda tudo o resto num stringbuilder
			StringBuilder content = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				content.append(line).append(System.lineSeparator());
			}

			// apaga o conteudo do ficheiro
			FileWriter arquivo = new FileWriter(fileS, false);

			// coloca de volta a info, mas o primeiro hmac (atualizado) passa para ultimo
			FileWriter writer = new FileWriter(fileS, true);
			writer.write(content.append(newHmac).toString() + System.lineSeparator());
			writer.close();

			this.previousHmac = newHmac;

		} catch (IOException e) {
			e.getMessage();
		}
	}
}
