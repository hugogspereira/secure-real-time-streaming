package hjStreamServer.movies;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import util.ConfigReader;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Properties;

/**
 * This class purpose is to encrypt movies so we can check later if we are doing right the project
 */
public class EncryptMovies {

	private static final String CIPHERSUITE = "CIPHERSUITE";
	private static final String KEY = "KEY";
	private static final String IV = "IV";
	private static final String INTEGRITY = "INTEGRITY";
	private static final String MACKEY = "MACKEY";

	public static void main( String []args ) {
		if (args.length != 2) {
			System.out.println("Erro, usar: EncryptMovies <movie> <movies-config>");
			System.exit(-1);
		}
		try {
			readProperties(args[0], args[1]);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}



	private static void readProperties(String fullMovieName, String moviesConfig) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		try {
			String[] path = fullMovieName.split("/");
			String movieName = path[path.length-1];
			String propsFileName = ConfigReader.read(moviesConfig, movieName);

			FileInputStream inputStream = new FileInputStream(ConfigReader.CONFIG_PATH+propsFileName);
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
				throw new Exception("Ciphersuite is invalid");
			}
			Cipher cipher = Cipher.getInstance(movieCiphersuite);
			if(movieIv == null) {
				throw new Exception("Iv is invalid");
			}
			IvParameterSpec ivSpec = new IvParameterSpec(movieIv.getBytes());
			if(movieKey == null) {
				throw new Exception("Key is invalid");
			}
			SecretKeySpec secretKey = new SecretKeySpec(movieKey.getBytes(), movieCiphersuite.split("/")[0]); // Necessário split? Testar!
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

			String[] fullPath = fullMovieName.split(".encrypted");
			File inputFile = new File(fullPath[0]);
			inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int) inputFile.length()];
			inputStream.read(inputBytes);

			String encryptedfile=fullMovieName;
			File encryptedFile = new File(encryptedfile);

			int size = inputBytes.length;

			if(movieIntegrity != null) {
				int integritySize, ctLength;
				byte[] cipherText, integrityData;
				if(movieMackey == null) {
					MessageDigest hash = MessageDigest.getInstance(movieIntegrity);
					integritySize = hash.getDigestLength();

					cipherText = new byte[cipher.getOutputSize(size + integritySize)];
					ctLength = cipher.update(inputBytes, 0, size, cipherText, 0);

					hash.update(inputBytes);
					integrityData = hash.digest();
				}
				else {
					Mac hMac = Mac.getInstance(movieIntegrity);
					Key hMacKey = new SecretKeySpec(movieKey.getBytes(), movieMackey);
					hMac.init(hMacKey);
					integritySize = hMac.getMacLength();

					cipherText = new byte[cipher.getOutputSize(size + integritySize)];
					ctLength = cipher.update(inputBytes, 0, size, cipherText, 0);

					hMac.update(inputBytes);
					integrityData = hMac.doFinal();
				}
				cipher.doFinal(integrityData, 0, integritySize, cipherText, ctLength);
				FileOutputStream outputStream = new FileOutputStream(encryptedFile);
				outputStream.write(integrityData);   // integrityData ??????? TODO

				inputStream.close();
				outputStream.close();
			}
			else {
				// É suposto ser uma excepção ? N percebi bem, supostamente no enunciado diz q só pode ser ou uma ou outra, mas a config de exemplo n tem nehnhuma.
				// Perguntar ao Professor
				throw new Exception("Not defined the integrity control in config file!");
				// Frames without integrity verification must be discarded, avoiding to send invalid frames to the media player
			}

		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.getMessage());
		}
	}

	private static String checkProperty(Properties properties, String property) {
		String res = properties.getProperty(property);
		if(res.equalsIgnoreCase("NULL")) {
			res = null;
		}
		return res;
	}

}
