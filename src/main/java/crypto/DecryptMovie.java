package crypto;

import util.ConfigReader;
import util.CryptoStuff;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Properties;

public class DecryptMovie {

	private static final String CIPHERSUITE = "CIPHERSUITE";
	private static final String KEY = "KEY";
	private static final String IV = "IV";
	private static final String INTEGRITY = "INTEGRITY";
	private static final String MACKEY = "MACKEY";

	private InputStream dataInputStream;
	Properties properties;

	public DecryptMovie(String movieName, String moviesConfig, String password) throws Exception {
		byte[] movieData;
		try {
			File inputFile = new File(movieName);
			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] data = new byte[(int) inputFile.length()];
			inputStream.read(data);

			String[] path = movieName.split("/");
			String movieNameAux = path[path.length - 1];

			InputStream inStream = new ByteArrayInputStream(
					ConfigReader.read(moviesConfig, movieNameAux, password).toByteArray());
			if (inStream == null) {
				System.err.println("Configuration Movie file not found!");
				System.exit(1);
			}
			properties = new Properties();
			properties.load(inStream);

			String movieCiphersuite, movieKey, movieIv;
			movieCiphersuite = checkProperty(properties, CIPHERSUITE);
			movieKey = checkProperty(properties, KEY);
			movieIv = checkProperty(properties, IV);

			if (movieCiphersuite == null) {
				throw new IOException("Ciphersuite is invalid");
			}
			Cipher cipher = Cipher.getInstance(movieCiphersuite);
			if (movieIv == null) {
				throw new IOException("Iv is invalid");
			}
			IvParameterSpec ivSpec = new IvParameterSpec(movieIv.getBytes());
			if (movieKey == null) {
				throw new IOException("Key is invalid");
			}
			SecretKeySpec secretKey = new SecretKeySpec(movieKey.getBytes(), movieCiphersuite.split("/")[0]);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

			movieData = CryptoStuff.decrypt(data, data.length, cipher, properties);

		} catch (NoSuchAlgorithmException e) {
			throw new IOException("Receive Encrypted data has failed! No such algorithm exception", e);
		} catch (NoSuchPaddingException e) {
			throw new IOException("Receive Encrypted data has failed! No such padding exception", e);
		} catch (InvalidKeyException e) {
			throw new IOException("Receive Encrypted data has failed! Invalid key exception", e);
		} catch (BadPaddingException e) {
			throw new IOException("Receive Encrypted data has failed! Bad padding exception", e);
		} catch (IllegalBlockSizeException e) {
			throw new IOException("Receive Encrypted data has failed! Illegal block size exception", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IOException("Receive Encrypted data has failed! Invalid algorithm parameter exception", e);
		}
		this.dataInputStream = new ByteArrayInputStream(movieData);
	}

	private String checkProperty(Properties properties, String property) {
		String res = properties.getProperty(property);
		if (res.equalsIgnoreCase("NULL")) {
			res = null;
		}
		return res;
	}

	public DataInputStream getDataInputStream() {
		if (dataInputStream == null) {
			System.out.println("Error occured during decryption of movie");
			System.exit(1);
		}
		return new DataInputStream(dataInputStream);
	}

}
