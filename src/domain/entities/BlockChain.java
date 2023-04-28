package domain.entities;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.LinkedList;
import java.util.List;
import catalogs.UserCatalog;
import enums.TransactionType;

public class BlockChain {

	private List<Block> blockchain;
	private Block currentBlock;
	private String prefixPath = "./src/blockchain/block_";
	private String sufixPath = ".blk";
	private long nextBlockID;
	private long nextTransactionID;
	private static BlockChain INSTANCE;
	private PrivateKey serverPK;
	// adicionar assinatura do servidor

	private BlockChain(PrivateKey serverPK) {
		this.blockchain = new LinkedList<>();

		// posteriormente estes numeros serao inicializados com os valores obtidos na
		// verificacao da blockchain
		this.nextBlockID = 1;
		this.nextTransactionID = 1;
		this.serverPK = serverPK;
	}

	public static BlockChain getInstance(PrivateKey serverPK) {
		if (INSTANCE == null)
			return INSTANCE = new BlockChain(serverPK);

		return INSTANCE;
	}

	public synchronized Block createBlock(byte[] previousHash) throws IOException {
		Block newBlock = null;
		String content = "";

		if (this.nextBlockID == 1) {
			newBlock = new Block(this.nextBlockID);
		} else {
			newBlock = new Block(this.nextBlockID, previousHash);
		}

		this.currentBlock = newBlock;
		this.blockchain.add(this.currentBlock);
		this.nextBlockID++;

		File newBlkFile = new File(this.getCurrentPath());
		newBlkFile.createNewFile();

		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(newBlkFile));
		
		oos.writeObject(newBlock);
		oos.close();

		return newBlock;
	}

	public synchronized Transaction createTransaction(TransactionType type, String wineID, int unitsNum, int unitPrice,
			String transactionOwner) throws IOException {
		return this.currentBlock.createTransaction(nextTransactionID, type, wineID, unitsNum, unitPrice,
				transactionOwner);
	}

	public synchronized void addTransaction(Transaction t)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

		int transactionsPerBlock = 5;

		if (this.currentBlock.getN_trx() == transactionsPerBlock) {

			Signature s = Signature.getInstance("SHA256withRSA");
			s.initSign(this.serverPK);

			String content = new String(Files.readAllBytes(Paths.get(this.getCurrentPath())));

			s.update(content.getBytes());
			byte[] signedContent = s.sign();
			
			this.currentBlock.setServerSignature(signedContent);
			
			ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(this.getCurrentPath()));
			
			oos.writeObject(this.currentBlock);
			oos.close();
		
			try {
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] previousHash = digest.digest(signedContent);
				this.createBlock(previousHash);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		this.currentBlock.addTransaction(t);
		this.nextTransactionID++;
		
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(this.getCurrentPath()));
		oos.writeObject(this.currentBlock);
		oos.close();

	}

	private synchronized String getCurrentPath() {
		return this.prefixPath + this.currentBlock.getId() + this.sufixPath;
	}

	/*
	 * percorrer os ficheiros usando os numeros, at� nao encontrar mais ficheiros
	 * 
	 * em cada ficheiro extrair a informacao e as transacoes e o bloco.
	 * 
	 * depois da blockchain ter sido carregada para a memoria, verificar as
	 * assinaturas com o hash do bloco seguinte. se nao bater certo, fechar o
	 * servidor
	 * 
	 */
	public synchronized void initializeBlockChain() throws IOException, ClassNotFoundException {
		Boolean firstTime = true;
		// Loop through all blockchain files
		while (true) {
			String filePath = this.prefixPath + this.nextBlockID + this.sufixPath;
			File file = new File(filePath);

			if (!file.exists() && firstTime) {
				createBlock(null);
				break;
			}

			if (!file.exists()) {
				break;
			}
			firstTime = false;
			ObjectInputStream oos = new ObjectInputStream(new FileInputStream(filePath));
			this.currentBlock = (Block) oos.readObject();
			this.blockchain.add(this.currentBlock);
			this.nextBlockID++;
			oos.close();
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Blockchain representation: \n\n");

		for (Block b : blockchain) {
			sb.append(b.toString());

			if (b.getServerSignature() != null)
				sb.append("\n--------------------------------\nServer Signature: ")
				.append(b.getServerSignature() + "\n--------------------------------\n\n");
		}

		return sb.toString();
	}

	public synchronized boolean verify(UserCatalog userCatalog) throws NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException {
	
		for (int i = 1; i <= this.nextBlockID - 2; i++) {
			
			Block currentBlock = this.getBlockById((long) i);
			Signature s = Signature.getInstance("SHA256withRSA");
			//Verificar assinaturas transacoes
			for (Transaction currentTransaction: currentBlock.getTransactions()) {
				
				String contentNotSigned = currentTransaction.getDataToSign();
				String transactionOwner = currentTransaction.getTransactionOwner();
				byte[] contentSigned = currentTransaction.getSignedContent();
				
				//aqui tem q se obter atraves do catalogo de utilizadores
				userCatalog.initializeUserCatalog();
				Certificate c = this.getCertificate(userCatalog.getCertificadoByID(transactionOwner));
				userCatalog.resetCatalog();
				
				PublicKey pk = c.getPublicKey();
				s.initVerify(pk);
				s.update(contentNotSigned.getBytes());
				if (!s.verify(contentSigned)) {
					System.out.println("Assinatura da transacao invalida");
					return false;
				}
			}
			
			byte[] serverSignature = currentBlock.getServerSignature();
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			
			Block nextBlock = this.getBlockById((long) (i+1));
			byte[] previousHash = nextBlock.getPreviousHash();
			
			if (!MessageDigest.isEqual(digest.digest(serverSignature), previousHash))
				return false;
		}

		return true;
		
	}
	
	private Certificate getCertificate(String certificateName) throws CertificateException, IOException {
		String path = "src/certificates/"+certificateName;
		FileInputStream is = new FileInputStream(path);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate c = cf.generateCertificate(is);
		is.close();
		return c;
	}
	
	private Block getBlockById(long id) {
		for (Block b: this.blockchain) {
			if (b.getId() == id)
				return b;
		}
		
		return null;
	}
}
