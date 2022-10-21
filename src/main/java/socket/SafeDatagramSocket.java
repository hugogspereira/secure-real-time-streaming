package socket;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import util.Utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.security.*;
import java.util.Properties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SafeDatagramSocket extends DatagramSocket {

    private static final String CIPHERSUITE = "ciphersuite";
    private static final String KEY = "key";
    private static final String IV = "iv";
    private static final String INTEGRITY = "integrity";
    private static final String MACKEY = "mackey";

    private String ciphersuite, key, iv, integrity, mackey;

    public SafeDatagramSocket() throws SocketException {
        super();
    }

    public SafeDatagramSocket(SocketAddress addr, String config) throws SocketException {
        super(addr);
        safeDSocketInitialization(addr, config);
    }

    public SafeDatagramSocket(InetSocketAddress addr, String config) throws SocketException {
        safeDSocketInitialization(addr, config);
    }

    private void safeDSocketInitialization(SocketAddress addr, String config) throws SocketException {
        Security.addProvider(new BouncyCastleProvider());  // Não acho que seja necessário, pois está no pom.xml!
        try {
            String propsFileName = Utils.createProps(addr, config);
            //System.out.println(Utils.CONFIG_PATH+propsFileName);
            InputStream inputStream = new FileInputStream(Utils.CONFIG_PATH+propsFileName);
            if (inputStream == null) {
                System.err.println("Configuration file not found!");
                System.exit(1);
            }
            Properties properties = new Properties();
            properties.load(inputStream);
            // TODO: O que acontece se houver mais do que um ficheiro com o mesmo nome?
            this.ciphersuite = properties.getProperty(CIPHERSUITE);
            System.out.println(ciphersuite);
            this.key = properties.getProperty(KEY);
            System.out.println(key);
            this.iv = properties.getProperty(IV);
            System.out.println(iv);
            this.integrity = properties.getProperty(INTEGRITY);
            System.out.println(integrity);
            this.mackey = properties.getProperty(MACKEY);
            System.out.println(mackey);
            
        } catch (Exception e) {
            throw new SocketException(e.getMessage());
        }
    }

    public void send(DatagramPacket p) throws IOException {   // Encrypt
        try {
            Cipher cipher = Cipher.getInstance(ciphersuite);
            if(iv == null) {
                throw new IOException("Iv is invalid");
            }
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
            if(key == null) {
                throw new IOException("Key is invalid");
            }
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ciphersuite.split("/")[0]); // Necessário split? Testar!
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            int size = p.getLength();
            byte[] data = p.getData();
            byte[] encryptedData;

            if(integrity != null) {
                int integritySize, ctLength;
                byte[] cipherText, integrityData;
                if(mackey == null) {
                    MessageDigest hash = MessageDigest.getInstance(integrity);
                    integritySize = hash.getDigestLength();

                    cipherText = new byte[cipher.getOutputSize(size + integritySize)];
                    ctLength = cipher.update(data, 0, size, cipherText, 0);

                    hash.update(data);
                    integrityData = hash.digest();
                }
                else {
                    Mac hMac = Mac.getInstance(mackey);
                    Key hMacKey = new SecretKeySpec(key.getBytes(), mackey);
                    hMac.init(hMacKey);
                    integritySize = hMac.getMacLength();

                    cipherText = new byte[cipher.getOutputSize(size + integritySize)];
                    ctLength = cipher.update(data, 0, size, cipherText, 0);

                    hMac.update(data);
                    integrityData = hMac.doFinal();
                }
                cipher.doFinal(integrityData, 0, integritySize, cipherText, ctLength);
                // See if size has become to small
                if(p.getLength() < integritySize) {
                    p.setLength(integritySize);
                    p.setData(integrityData);
                }
            }
            else {
                // É suposto ser uma excepção ? N percebi bem, supostamente no enunciado diz q só pode ser ou uma ou outra, mas a config de exemplo n tem nehnhuma.
                // Perguntar ao Professor
                throw new IOException("Not defined the integrity control in config file!");
                // Frames without integrity verification must be discarded, avoiding to send invalid frames to the media player
            }
            super.send(p);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IOException("Send Encrypted data has failed! No such algorithm exception", e);
        }
        catch (NoSuchPaddingException e) {
            throw new IOException("Send Encrypted data has failed! No such padding exception", e);
        }
        catch (InvalidKeyException e) {
            throw new IOException("Send Encrypted data has failed! Invalid key exception", e);
        }
        catch (BadPaddingException e) {
            throw new IOException("Send Encrypted data has failed! Bad padding exception", e);
        }
        catch (IllegalBlockSizeException e) {
            throw new IOException("Send Encrypted data has failed! Illegal block size exception", e);
        }
        catch (InvalidAlgorithmParameterException e) {
            throw new IOException("Send Encrypted data has failed! Invalid algorithm parameter exception", e);
        } catch (ShortBufferException e) {
            throw new IOException("Send Encrypted data has failed! Buffer is to short exception", e);
        }
    }

    public void receive(DatagramPacket p) throws IOException { // Decrypt
        try {
            Cipher cipher = Cipher.getInstance(ciphersuite);
            if(iv == null) {
                throw new IOException("Iv is invalid");
            }
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
            if(key == null) {
                throw new IOException("Key is invalid");
            }
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ciphersuite.split("/")[0]); // Necessário split? Testar!
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            int size = p.getLength();
            byte[] data = p.getData();
            byte[] encryptedData;

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
                        // Fazer setLength() ?
                        p.setData(movieData);
                    }
                    else { // Não mandar o packet! Integrity check failed!
                        return;
                    }
                }
                else {
                    Mac hMac = Mac.getInstance(mackey);
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
                        // Fazer setLength() ?
                        p.setData(movieData);
                    }
                    else {  // Não mandar o packet! Integrity check failed!
                        return;
                    }
                }
            }
            else {
                // É suposto ser uma excepção ? N percebi bem, supostamente no enunciado diz q só pode ser ou uma ou outra, mas a config de exemplo n tem nehnhuma.
                // Perguntar ao Professor
                throw new IOException("Not defined the integrity control in config file!");
                // Frames without integrity verification must be discarded, avoiding to send invalid frames to the media player
            }
            super.receive(p);
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
}
