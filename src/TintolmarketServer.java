
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Scanner;

public class TintolmarketServer {

	public static void main(String[] args) {
		System.out.println("servidor: main");
		TintolmarketServer tintolServer = new TintolmarketServer();
		tintolServer.startServer();
	}

	public void startServer() {
		ServerSocket tintolSocket = null;

		try {
			
			tintolSocket = new ServerSocket(12345);
			tintolSocket.setReuseAddress(true);
	
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		while (true) {
			try {
				
				Socket inSocket = tintolSocket.accept();
				System.out.println("New client connected " + inSocket.getInetAddress().getHostAddress());
				ClientHandler clientSock = new ClientHandler(inSocket);
				clientSock.start();
				
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		// tintolSocket.close();
	}

	class ClientHandler extends Thread {

		private Socket socket = null;
		private ObjectOutputStream outStream;
		private ObjectInputStream inStream;
		
		ClientHandler(Socket tintolSocket) {
			socket = tintolSocket;
			
			try {
				outStream = new ObjectOutputStream(socket.getOutputStream());
				inStream = new ObjectInputStream(socket.getInputStream());
			} catch (IOException e) {
				e.printStackTrace();
				System.out.println("Erro nas streams da socket");
			}
		}

		public void run() {
			try {
				
				String clientID = null;
				String password = null;

				try {
					clientID = (String) inStream.readObject();
					password = (String) inStream.readObject();
				} catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}

				File clientCatalog = new File("./src/usersCatalog.txt");

				Scanner fileSc = new Scanner(clientCatalog);
				Boolean registed = false;
				Boolean isUserFileEmpty = true;

				while (fileSc.hasNextLine()) {

					isUserFileEmpty = false;
					String actual = fileSc.nextLine();
					String cID = actual.split(":")[0];
					String givenPass = actual.split(":")[1];

					if (clientID.equals(cID) && password.equals(givenPass)) {
						registed = true;
						break;
					} else if (clientID.equals(cID) && !password.equals(givenPass)) {
						outStream.writeObject("erroPass");
						fileSc.close();
						socket.close();
						// System.out.println("Programa Terminado");

						System.exit(0);
					}
				}

				if (registed) {

					outStream.writeObject("registado");

				} else {
					outStream.writeObject("NovoRegisto"); // Cliente registado

					String newClient = "";
					if (isUserFileEmpty) {
						newClient = new StringBuilder().append(clientID + ":" + password).toString();
					} else {
						newClient = new StringBuilder().append("\n" + clientID + ":" + password).toString();
					}

					OutputStream clientRegister = new FileOutputStream(clientCatalog, true);
					clientRegister.write(newClient.getBytes(), 0, newClient.length());
					clientRegister.close();

				}

				interactWUser(clientID);

				fileSc.close();
				socket.close();

			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		private void interactWUser(String clientID) {

			String menu = getMenu();
			String userAction = "";

			try {
				while (!userAction.equals("exit")) {

					outStream.writeObject(menu);

					try {
						userAction = (String) inStream.readObject();
					} catch (ClassNotFoundException e) {
						e.printStackTrace();
					}

					String[] userActionSplited = userAction.split(" ");
					int arraySize = userActionSplited.length;

					if (userActionSplited[0].equals("add") || userActionSplited[0].equals("a") && arraySize == 3) {
						outStream.writeObject(
								addFunc("./src/wineCatalog.txt", userActionSplited[1], userActionSplited[2]));

					} else if (userActionSplited[0].equals("sell") || userActionSplited[0].equals("s") && arraySize == 4) {
						outStream.writeObject(sellFunc("./src/wineCatalog.txt", "./src/wineMarket.txt",
								userActionSplited[1], Integer.parseInt(userActionSplited[2]),
								Integer.parseInt(userActionSplited[3]), clientID));

					} else if (userActionSplited[0].equals("view") || userActionSplited[0].equals("v") && arraySize == 2) {
						outStream.writeObject(viewFunc("./src/wineCatalog.txt", "./src/wineMarket.txt", userActionSplited[1]));

					} else if (userActionSplited[0].equals("buy") || userActionSplited[0].equals("b") && arraySize == 4) {
                        outStream.writeObject(buyFunc("./src/wineMarket.txt", userActionSplited[1],
                                Integer.parseInt(userActionSplited[3]), userActionSplited[2], clientID));

					} else if (userActionSplited[0].equals("wallet") || userActionSplited[0].equals("w")) {
						walletFunc("./src/userWallet.txt", clientID);

					} else if (userActionSplited[0].equals("classify") || userActionSplited[0].equals("c")) {
						outStream.writeObject(classifyFunc("./src/wineCatalog.txt", userActionSplited[1],
								Integer.parseInt(userActionSplited[2])));

					} else if (userActionSplited[0].equals("talk") || userActionSplited[0].equals("t")) {
						String message = Arrays
								.toString(Arrays.copyOfRange(userActionSplited, 1, userActionSplited.length));
						talkFunc("./src/usersChat.txt", message);

					} else if (userActionSplited[0].equals("read") || userActionSplited[0].equals("r")) {
						readFunc("./src/usersChat.txt");

					} else if (userActionSplited[0].equals("exit") || userActionSplited[0].equals("e")) {
						break;

					} else {
						outStream.writeObject("Invalid action.\n");
						continue;
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		
		private void editFile(String wineCatalogFile, String sellFileLine, int value, int quantity, String operation) {

			File winesCatalog = new File(wineCatalogFile);
			Scanner winesSc = null;

			try {
				winesSc = new Scanner(winesCatalog);
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			}

			Boolean isFound = false;
			while (winesSc.hasNextLine() && !isFound) {

				String wineFileLine = winesSc.nextLine();
				String[] wineFileLineSplitted = wineFileLine.split(";");

				if (sellFileLine.equals(wineFileLine)) {

					File fileToBeModified = new File(wineCatalogFile);
					BufferedReader reader = null;
					FileWriter writer = null;

					isFound = true;
					String oldContent = "";

					try {
						reader = new BufferedReader(new FileReader(fileToBeModified));

						// Reading all the lines of input text file into oldContent

						String line = reader.readLine();

						while (line != null) {

							oldContent = oldContent + line + System.lineSeparator();
							line = reader.readLine();
						}

						String newContentWithoutNewLine = "";

						if (operation.equals("buy")) {
							
							// Replacing oldString with newString in the oldContent
							String newString = (wineFileLineSplitted[0] + ";" + wineFileLineSplitted[1] + ";" + value
									+ ";" + String.valueOf(Integer.parseInt(wineFileLineSplitted[3]) - quantity) + ";"
									+ wineFileLineSplitted[4] + ";" + wineFileLineSplitted[5]);
							String newContent = oldContent.replace(wineFileLine, newString);
							newContentWithoutNewLine = newContent.substring(0, newContent.length() - 2);
							// Rewriting the input text file with newContent
							
						} else if (operation.equals("sell")) {
							
							String newString = (wineFileLineSplitted[0] + ";" + wineFileLineSplitted[1] + ";" + value
									+ ";" + String.valueOf(Integer.parseInt(wineFileLineSplitted[3]) + quantity) + ";"
									+ wineFileLineSplitted[4] + ";" + wineFileLineSplitted[5]);
							String newContent = oldContent.replace(wineFileLine, newString);
							newContentWithoutNewLine = newContent.substring(0, newContent.length() - 2);
							
						}

						writer = new FileWriter(fileToBeModified);

						writer.write(newContentWithoutNewLine);
					} catch (IOException e) {
						e.printStackTrace();
					} finally {
						try {
							// Closing the resources

							reader.close();

							writer.close();
						} catch (IOException e) {
							e.printStackTrace();

						}
					}
				}

			}
		}

		private String addFunc(String filename, String wine, String image) throws IOException {

			File winesCatalog = new File(filename);
			Scanner winesSc = null;

			try {
				winesSc = new Scanner(winesCatalog);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}

			Boolean isWineFileEmpty = true;
			String wineOfFile = "";
			
			while (winesSc.hasNextLine()) {
				isWineFileEmpty = false;
				wineOfFile = winesSc.nextLine().split(";")[0];
				if (wine.equals(wineOfFile))
					return "This wine already exists.";
			}

			String wineRegist = "";
			if (isWineFileEmpty) {
				wineRegist = (wine + ";" + image + ";0:0");
			} else {
				wineRegist = ("\n" + wine + ";" + image + ";0:0");
			}

			OutputStream addWine = new FileOutputStream(filename, true);
			addWine.write(wineRegist.getBytes(), 0, wineRegist.length());
			addWine.close();

			return "Wine added.";
		}

		private String sellFunc(String filenameToRead, String filenameToWrite, String wine, int value, int quantity,
				String clientID) throws IOException {

			File winesCatalog = new File(filenameToRead);
			Scanner winesSc = null;

			try {
				winesSc = new Scanner(winesCatalog);
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			}

			Boolean isFound = false;
			String[] wineFileLineSplitted = null;

			while (winesSc.hasNextLine() && !isFound) {

				String wineFileLine = winesSc.nextLine();
				wineFileLineSplitted = wineFileLine.split(";");

				if (wine.equals(wineFileLineSplitted[0])) { // nome vinho
					isFound = true;

				}
			}

			File winesCatalogSell = new File(filenameToWrite);
			Scanner winesToSellSc = null;

			try {
				winesToSellSc = new Scanner(winesCatalogSell);
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			}

			Boolean isWineFileEmpty = true;

			if (winesToSellSc.hasNextLine()) {
				isWineFileEmpty = false;
			}

			String wineRegist = "";
			Boolean isIn = false;

			if (isFound) {

				while (winesToSellSc.hasNextLine()) {
					String sellCheck = winesToSellSc.nextLine();
					String[] sellCheckSplitted = sellCheck.split(";");

					if (wine.equals(sellCheckSplitted[0]) && clientID.equals(sellCheckSplitted[5])) {
						isIn = true;
						editFile(filenameToWrite, sellCheck, value, quantity, "sell");
						return "Wine is now on sale.";
					}
				}

				if (!isIn) {
					if (isWineFileEmpty) {
						wineRegist = (wine + ";" + wineFileLineSplitted[1] + ";" + value + ";" + quantity + ";"
								+ wineFileLineSplitted[2] + ";" + clientID);
					} else {
						wineRegist = ("\n" + wine + ";" + wineFileLineSplitted[1] + ";" + value + ";" + quantity + ";"
								+ wineFileLineSplitted[2] + ";" + clientID);
					}
					OutputStream addWineSell = new FileOutputStream(filenameToWrite, true);
					addWineSell.write(wineRegist.getBytes(), 0, wineRegist.length());
					addWineSell.close();

					return "Wine is now on sale.";
				}
			}

			return "This wine doesnt exist.";
		}

		private String viewFunc(String wineCatalogName, String wineMarketName, String wine) {

			File wineCatalogFile = new File(wineCatalogName);
			File wineMarketFile = new File(wineMarketName);			
			StringBuilder result = new StringBuilder();
			
			Scanner catalogSc = null;			
			try {
				catalogSc = new Scanner(wineCatalogFile);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}

			Scanner marketSc = null;
			try {
				marketSc = new Scanner(wineMarketFile);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}
			
			String[] wineMarketLine = null;
			while (catalogSc.hasNextLine()) {
				wineMarketLine = catalogSc.nextLine().split(";");
				if (wineMarketLine[0].equals(wine));
					break;
			}
			
			while (marketSc.hasNextLine()) {

				String wineFileLine = marketSc.nextLine();
				String[] wineFileLineSplitted = wineFileLine.split(";");

				if (wine.equals(wineFileLineSplitted[0])) {

					result.append(wine + " information:\n Image: " + wineFileLineSplitted[1]
							+ "\n Average Classification: " + String.format("%.2f", Float.parseFloat(wineMarketLine[2])/Float.parseFloat(wineMarketLine[3])));

					if (Integer.parseInt(wineFileLineSplitted[3]) > 0)
						result.append("\n Wine seller " + wineFileLineSplitted[4] + "\n Price: " + wineFileLineSplitted[2]
								+ "\n In Stock: " + wineFileLineSplitted[3]);
					
					return result.toString();
				}
			}
			
			marketSc.close();
			catalogSc.close();
			
			return result.append("This Wine doesnt exist").toString();
		}

        private String buyFunc(String filename, String wine, int quantity, String sellerID, String clientID)
                throws IOException {

	            File winesCatalogBuy = new File(filename);
	            Scanner winesToBuySc = null;
	
	            try {
	                winesToBuySc = new Scanner(winesCatalogBuy);
	            } catch (FileNotFoundException e1) {
	                e1.printStackTrace();
	            }
	
	            Boolean isFound = false;
	            Boolean isPurchasable = false;
	            String[] wineFileLineSplitted = null;
	            String wineRequired = "";
	
	            while (winesToBuySc.hasNextLine()) {
	
	                String wineFileLine = winesToBuySc.nextLine();
	                wineFileLineSplitted = wineFileLine.split(";");
	
	                if (wine.equals(wineFileLineSplitted[0]) && sellerID.equals(wineFileLineSplitted[5])) {
	                    wineRequired = wineFileLine;
	                    isFound = true;
	                    if (walletFunc(filename, clientID) >= Integer.parseInt(wineFileLineSplitted[2])
	                            && quantity <= Integer.parseInt(wineFileLineSplitted[3])) {
	                        isPurchasable = true;
	                        break;
	                    }
	                }
	
	                if (!isFound && !isPurchasable) {
	                    isFound = false;
	                    isPurchasable = false;
	                }
	
	            }
	
	            if (!isFound || !isPurchasable) {
	                return "\nReasons why you can't buy this wine:\n\n"
	                        + " - This wine does not exists or it isn't available on this seller's stock;\n"
	                        + " - Quantity not available or insufficient funds. SEU POBREEEE.";
	            }
	
	            editFile(filename, wineRequired, Integer.parseInt(wineFileLineSplitted[2]), quantity, "buy");
	            return "Wine purchased.";

        }

		private int walletFunc(String filename, String clientID) {
			// TODO Auto-generated method stub
			return 200;
		}

		private String classifyFunc(String wineCatalogFile, String wine, int stars) {
			
			if (stars < 0 || stars > 5)
				return "Your classification must be from 0 to 5";
			
			File winesCatalog = new File(wineCatalogFile);
			
			Scanner winesSc = null;

			try {
				winesSc = new Scanner(winesCatalog);
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			}

			Boolean isFound = false;
			while (winesSc.hasNextLine() && !isFound) {

				String wineFileLine = winesSc.nextLine();
				String[] wineFileLineSplitted = wineFileLine.split(";");

				if (wineFileLineSplitted[0].equals(wine)) {
					
					File fileToBeModified = new File(wineCatalogFile);
					BufferedReader reader = null;
					FileWriter writer = null;
	
					isFound = true;
					String oldContent = "";
	
					try {
						reader = new BufferedReader(new FileReader(fileToBeModified));
		
						String line = reader.readLine();
						// Reading all the lines of input text file into oldContent
						while (line != null) {
							oldContent = oldContent + line + System.lineSeparator();
							line = reader.readLine();
						}
	
						String newContentWithoutNewLine = "";

						// Replacing oldString with newString in the oldContent
						String newString = wineFileLineSplitted[0] + ";" + wineFileLineSplitted[1] +
								";" + (String.valueOf(Integer.parseInt(wineFileLineSplitted[2])+stars)) +
								";" + String.valueOf(Integer.parseInt(wineFileLineSplitted[3])+1);
						String newContent = oldContent.replace(wineFileLine, newString);
						newContentWithoutNewLine = newContent.substring(0, newContent.length() - 2);
						
						// Rewriting the input text file with newContent
						writer = new FileWriter(fileToBeModified);
						writer.write(newContentWithoutNewLine);
						
					} catch (IOException e) {
						e.printStackTrace();
					} finally {
						try {	
							reader.close();
							writer.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}
			}
			
			return "Classification atributed";
		}

		private boolean talkFunc(String filename, String message) {
			// TODO Auto-generated method stub
			return false;
		}

		private boolean readFunc(String filename) {
			// TODO Auto-generated method stub
			return false;
		}

		private void exitFunc(Scanner sc1, Socket sock) throws IOException {
			sc1.close();
			sock.close();
			System.exit(0);
		}
		


		private String getMenu() {
			return "\nActions:\nadd <wine> <image>\n" + "sell <wine> <value> <quantity>\n" + "view <wine>\n"
					+ "buy <wine> <seller> <quantity>\n" + "wallet\n" + "classify <wine> <stars>\n"
					+ "talk <user> <message>\n" + "read\n" + "exit\n";
		}

	}

}
