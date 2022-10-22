package socket;

import util.ConfigReader;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Properties;

public class DataInputDecryptStream {

	private static final String CIPHERSUITE = "CIPHERSUITE";
	private static final String KEY = "KEY";
	private static final String IV = "IV";
	private static final String INTEGRITY = "INTEGRITY";
	private static final String MACKEY = "MACKEY";

	private InputStream dataInputStream;

	public DataInputDecryptStream(String movieName, String moviesConfig) throws Exception {
		byte[] movieData;
		try {
			File inputFile = new File(movieName);
			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] data = new byte[(int) inputFile.length()];
			inputStream.read(data);
			System.out.println("DATA LENGTH: "+data.length);

			String[] path = movieName.split("/");
			String movieNameAux = path[path.length-1];
			String propsFileName = ConfigReader.read(moviesConfig, movieNameAux);

			inputStream = new FileInputStream(ConfigReader.CONFIG_PATH+propsFileName);
			if (inputStream == null) {
				System.err.println("Configuration Movie file not found!");
				System.exit(1);
			}
			Properties properties = new Properties();
			properties.load(inputStream);

			String movieCiphersuite, movieKey, movieIv, movieIntegrity, movieMackey;
			movieCiphersuite = checkProperty(properties,CIPHERSUITE);
			movieKey = checkProperty(properties,KEY);
			movieIv = checkProperty(properties,IV);
			movieIntegrity = checkProperty(properties,INTEGRITY);
			movieMackey = checkProperty(properties,MACKEY);

			if(movieCiphersuite == null){
				throw new IOException("Ciphersuite is invalid");
			}
			Cipher cipher = Cipher.getInstance(movieCiphersuite);
			if(movieIv == null) {
				throw new IOException("Iv is invalid");
			}
			IvParameterSpec ivSpec = new IvParameterSpec(movieIv.getBytes());
			if(movieKey == null) {
				throw new IOException("Key is invalid");
			}
			SecretKeySpec secretKey = new SecretKeySpec(movieKey.getBytes(), movieCiphersuite);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

			int size = data.length;

			if(movieIntegrity != null) {
				byte[] decryptedData, messageIntegrity;
				int messageLength;
				if(movieMackey == null) {
					MessageDigest hash = MessageDigest.getInstance(movieIntegrity);

					decryptedData = cipher.doFinal(data);
					messageLength = decryptedData.length - hash.getDigestLength();
					movieData = new byte[messageLength];
					hash.update(decryptedData, 0, messageLength);

					messageIntegrity = new byte[hash.getDigestLength()];
					System.arraycopy(decryptedData, messageLength, messageIntegrity, 0, messageIntegrity.length);

					if(MessageDigest.isEqual(hash.digest(), messageIntegrity)) {
						System.arraycopy(decryptedData, 0, movieData, 0, messageLength);
					}
					else { // Não mandar o packet! Integrity check failed!
						movieData = null;
					}
				}
				else {
					Mac hMac = Mac.getInstance(movieIntegrity);
					Key hMacKey = new SecretKeySpec(movieKey.getBytes(), movieMackey);

					decryptedData = cipher.doFinal(data, 0, size);
					messageLength = decryptedData.length - hMac.getMacLength();
					movieData = new byte[messageLength];

					hMac.init(hMacKey);
					hMac.update(decryptedData, 0, messageLength);

					messageIntegrity = new byte[hMac.getMacLength()];
					System.arraycopy(decryptedData, messageLength, messageIntegrity, 0, messageIntegrity.length);

					if(MessageDigest.isEqual(hMac.doFinal(), messageIntegrity)) {
						System.arraycopy(decryptedData, 0, movieData, 0, messageLength);
					}
					else {  // Não mandar o packet! Integrity check failed!
						movieData = null;
					}
				}
			}
			else {
				// É suposto ser uma excepção ? N percebi bem, supostamente no enunciado diz q só pode ser ou uma ou outra, mas a config de exemplo n tem nehnhuma.
				// Perguntar ao Professor
				throw new IOException("Not defined the integrity control in config file!");
				// "Frames without integrity verification must be discarded, avoiding to send invalid frames to the media player"
			}
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException("Receive Encrypted data has failed! No such algorithm exception", e);
		}
		catch (NoSuchPaddingException e) {
			throw new IOException("Receive Encrypted data has failed! No such padding exception", e);
		}
		catch (InvalidKeyException e) {
			throw new IOException("Receive Encrypted data has failed! Invalid key exception", e);
		}
		catch (BadPaddingException e) {
			throw new IOException("Receive Encrypted data has failed! Bad padding exception", e);
		}
		catch (IllegalBlockSizeException e) {
			throw new IOException("Receive Encrypted data has failed! Illegal block size exception", e);
		}
		catch (InvalidAlgorithmParameterException e) {
			throw new IOException("Receive Encrypted data has failed! Invalid algorithm parameter exception", e);
		}
		System.out.println("MOVIE LENGTH: "+movieData.length);
		this.dataInputStream = new ByteArrayInputStream(movieData);
	}

	private String checkProperty(Properties properties, String property) {
		String res = properties.getProperty(property);
		if(res.equalsIgnoreCase("NULL")) {
			res = null;
		}
		return res;
	}

	public DataInputStream getDataInputStream() {
		if(dataInputStream == null) {
			System.out.println("Error occured during decryption of movie");
			System.exit(1);
		}
		return new DataInputStream(dataInputStream);
	}

}
