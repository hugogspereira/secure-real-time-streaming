package util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MovieDecriptor {

    private static final String CIPHERSUITE = "CIPHERSUITE";
    private static final String KEY = "KEY";
    private static final String IV = "IV";
    private static final String INTEGRITY = "INTEGRITY";
    private static final String MACKEY = "MACKEY";

    public MovieDecriptor(){}

    /*public static byte[] decrypt(String moviesConfig, String movieName) throws Exception{

        String[] path = movieName.split("/");
        //System.out.println(Utils.CONFIG_PATH+propsFileName);
        FileInputStream inputStream = new FileInputStream(ConfigReader.read(moviesConfig, path[path.length-1]).toByteArray());
        
        Properties properties = new Properties();
        properties.load(inputStream);

        System.out.println("-----------------\nMOVIE");
        String ciphersuite = checkProperty(properties,CIPHERSUITE);
        String key = checkProperty(properties,KEY);
        String iv = checkProperty(properties,IV);
        String integrity = checkProperty(properties,INTEGRITY);
        String mackey = checkProperty(properties,MACKEY);

        System.out.println(ciphersuite);
        System.out.println(key);
        System.out.println(iv);
        System.out.println(integrity);
        System.out.println(mackey);
        System.out.println("-----------------");

        try {
            if(ciphersuite == null){
                throw new IOException("Ciphersuite is invalid");
            }
            Cipher cipher = Cipher.getInstance(ciphersuite);
            if(iv == null) {
                throw new IOException("Iv is invalid");
            }
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
            if(key == null) {
                throw new IOException("Key is invalid");
            }

            inputStream = new FileInputStream(movieName);
            byte[] data = inputStream.readAllBytes();

            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ciphersuite.split("/")[0]); // Necessário split? Testar!
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            int size = data.length;

            if(integrity != null) {
                byte[] decryptedData, messageIntegrity, movieData;
                int messageLength;
                if(mackey == null) {
                    MessageDigest hash = MessageDigest.getInstance(integrity);

                    decryptedData = cipher.doFinal(data);
                    messageLength = decryptedData.length - hash.getDigestLength();
                    movieData = new byte[messageLength];
                    hash.update(decryptedData, 0, messageLength);

                    messageIntegrity = new byte[hash.getDigestLength()];
                    System.arraycopy(decryptedData, messageLength, messageIntegrity, 0, messageIntegrity.length);

                    if(MessageDigest.isEqual(hash.digest(), messageIntegrity)) {
                        System.arraycopy(decryptedData, 0, movieData, 0, messageLength);
                        data = movieData;
                    }
                    else { // Não mandar o packet! Integrity check failed!
                        inputStream.close();
                        throw new Exception("Integrity check failed!");
                    }
                }
                else {
                    Mac hMac = Mac.getInstance(integrity);
                    Key hMacKey = new SecretKeySpec(key.getBytes(), mackey);

                    decryptedData = cipher.doFinal(data, 0, size);
                    messageLength = decryptedData.length - hMac.getMacLength();
                    movieData = new byte[messageLength];

                    hMac.init(hMacKey);
                    hMac.update(decryptedData, 0, messageLength);

                    messageIntegrity = new byte[hMac.getMacLength()];
                    System.arraycopy(decryptedData, messageLength, messageIntegrity, 0, messageIntegrity.length);

                    if(MessageDigest.isEqual(hMac.doFinal(), messageIntegrity)) {
                        System.arraycopy(decryptedData, 0, movieData, 0, messageLength);
                        data = movieData;
                    }
                    else {  // Não mandar o packet! Integrity check failed!
                        inputStream.close();
                        throw new Exception("Integrity check failed!");
                    }
                }
            }
            else {
                // É suposto ser uma excepção ? N percebi bem, supostamente no enunciado diz q só pode ser ou uma ou outra, mas a config de exemplo n tem nehnhuma.
                // Perguntar ao Professor
                inputStream.close();
                throw new IOException("Not defined the integrity control in config file!");
                // "Frames without integrity verification must be discarded, avoiding to send invalid frames to the media player"
            }

            inputStream.close();
            return data;

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
    
    }

    private static String checkProperty(Properties properties, String property) {
        String res = properties.getProperty(property);
        if(res.equalsIgnoreCase("NULL")) {
            res = null;
        }
        return res;
    }
     */
}
