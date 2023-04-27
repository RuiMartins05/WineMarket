package catalogs;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Scanner;

import domain.entities.FileEncryptorDecryptor;
import domain.entities.User;

public class UserCatalog {

	private String usersStr;
	private String userWalletsStr;
	private String passwordUsers;

	private static UserCatalog INSTANCE;
	private ArrayList<User> userCatalog;

	private UserCatalog(String usersStr, String userWalletsStr, String passwordCifra) {
		userCatalog = new ArrayList<User>();
		this.usersStr = usersStr;
		this.userWalletsStr = userWalletsStr;
		this.passwordUsers = passwordCifra;
	}

	public static UserCatalog getInstance(String usersStr, String userWalletsStr, String passwordCifra) {
		if (INSTANCE == null)
			INSTANCE = new UserCatalog(usersStr, userWalletsStr, passwordCifra);

		return INSTANCE;
	}

	public void initializeUserCatalog() {

		Scanner usersCatalogDecrypted = new Scanner(FileEncryptorDecryptor.decryptUsersCat(passwordUsers));

		while (usersCatalogDecrypted.hasNextLine()) {
			String[] currentLine = usersCatalogDecrypted.nextLine().split(":");
			this.add(new User(currentLine[0], currentLine[1]));
		}

		usersCatalogDecrypted.close();

		File userWallets = new File(this.userWalletsStr);

		Scanner walletSc = null;
		try {
			walletSc = new Scanner(userWallets);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

		while (walletSc.hasNextLine()) {
			String[] currentLine = walletSc.nextLine().split(":");
			this.getUserByID(currentLine[0]).setBalance(Integer.parseInt(currentLine[1]));
		}

		walletSc.close();
	}

	public synchronized User getUserByID(String id) {

		for (User u : userCatalog)
			if (u.getID().equals(id))
				return u;

		return null;

	}

	public synchronized int watchWallet(User u) {
		return u.getBalance();
	}

	public synchronized void add(User user) {
		userCatalog.add(user);
	}

	public synchronized Boolean exists(String clientID) {
		return INSTANCE.getUserByID(clientID) != null;
	}

	public synchronized int getSize() {
		return userCatalog.size();
	}

	public synchronized String getCertificadoByID(String ID) {
		for (User u : this.userCatalog)
			if (u.getID().equals(ID))
				return u.getCertificado();
		return null;
	}

	public void registNewUser(String clientID, String certificadoStr) throws IOException {

		String userCatDesencrypted = FileEncryptorDecryptor.decryptUsersCat(certificadoStr);

		File usersCatalog = new File(this.usersStr);

		String newClient = "\n" + clientID + ":" + certificadoStr;

		if (this.getSize() == 0)
			newClient = clientID + ":" + certificadoStr;

		String newDataToCat = userCatDesencrypted + newClient;

		OutputStream clientRegister = new FileOutputStream(usersCatalog);
		synchronized (clientRegister) {
			clientRegister.write(newDataToCat.getBytes(), 0, newDataToCat.length());
			clientRegister.close();
		}

		FileEncryptorDecryptor.encryptUsersCat(this.usersStr, this.passwordUsers);
	}

	public void registNewWallet(String clientID) throws IOException {
		File userWallets = new File(this.userWalletsStr);

		String usersBalance = "\n" + clientID + ":200";
		if (this.getSize() == 0)
			usersBalance = clientID + ":200";

		OutputStream wallet = new FileOutputStream(userWallets, true);
		synchronized (wallet) {
			wallet.write(usersBalance.getBytes(), 0, usersBalance.length());
			wallet.close();
		}
	}

}