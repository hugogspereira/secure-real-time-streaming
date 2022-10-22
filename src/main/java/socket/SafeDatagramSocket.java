package socket;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import util.ConfigReader;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Properties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SafeDatagramSocket extends DatagramSocket {

    private static final String CIPHERSUITE = "CIPHERSUITE";
    private static final String KEY = "KEY";
    private static final String IV = "IV";
    private static final String INTEGRITY = "INTEGRITY";
    private static final String MACKEY = "MACKEY";

    private String boxCiphersuite, boxKey, boxIv, boxIntegrity, boxMackey;
    private String movieCiphersuite, movieKey, movieIv, movieIntegrity, movieMackey;

    public SafeDatagramSocket() throws SocketException {
        super();
    }

    public SafeDatagramSocket(SocketAddress addr, String config) throws SocketException {
        super(addr);
        readProperties(addr, config, null, null);
    }

    public SafeDatagramSocket(InetSocketAddress addr, String boxConfig, String movieName, String moviesConfig) throws SocketException {
        readProperties(addr, boxConfig, movieName, moviesConfig);
    }

    private void readProperties(SocketAddress addr, String boxConfig, String movieName, String moviesConfig) throws SocketException {
        Security.addProvider(new BouncyCastleProvider());

        try {
            String propsFileName = ConfigReader.read(boxConfig, addr.toString().split("/")[1]);
            //System.out.println(Utils.CONFIG_PATH+propsFileName);
            InputStream inputStream = new FileInputStream(ConfigReader.CONFIG_PATH+propsFileName);
            if (inputStream == null) {
                System.err.println("Configuration Box file not found!");
                System.exit(1);
            }
            Properties properties = new Properties();
            properties.load(inputStream);

            System.out.println("-----------------\nBOX");
            this.boxCiphersuite = checkProperty(properties,CIPHERSUITE);
            this.boxKey = checkProperty(properties,KEY);
            this.boxIv = checkProperty(properties,IV);
            this.boxIntegrity = checkProperty(properties,INTEGRITY);
            this.boxMackey = checkProperty(properties,MACKEY);

            System.out.println(boxCiphersuite);
            System.out.println(boxKey);
            System.out.println(boxIv);
            System.out.println(boxIntegrity);
            System.out.println(boxMackey);
            System.out.println("-----------------");

            if(movieName != null) {
                String[] path = movieName.split("/");
                propsFileName = ConfigReader.read(moviesConfig, path[path.length-1]);
                //System.out.println(Utils.CONFIG_PATH+propsFileName);
                inputStream = new FileInputStream(ConfigReader.CONFIG_PATH+propsFileName);
                if (inputStream == null) {
                    System.err.println("Configuration Movie file not found!");
                    System.exit(1);
                }
                properties = new Properties();
                properties.load(inputStream);

                System.out.println("-----------------\nMOVIE");
                this.movieCiphersuite = checkProperty(properties,CIPHERSUITE);
                this.movieKey = checkProperty(properties,KEY);
                this.movieIv = checkProperty(properties,IV);
                this.movieIntegrity = checkProperty(properties,INTEGRITY);
                this.movieMackey = checkProperty(properties,MACKEY);

                System.out.println(movieCiphersuite);
                System.out.println(movieKey);
                System.out.println(movieIv);
                System.out.println(movieIntegrity);
                System.out.println(movieMackey);
                System.out.println("-----------------");
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new SocketException(e.getMessage());
        }
    }

    private String checkProperty(Properties properties, String property) {
        String res = properties.getProperty(property);
        if(res.equalsIgnoreCase("NULL")) {
            res = null;
        }
        return res;
    }

    public void send(DatagramPacket p) throws IOException {   // Encrypt
        // Desincripta os packets do movie q está encriptado !
        byte[] data = decrypt(true, p.getData());
        if(data == null)
            return;

        // Depois envia-se o data packet com os dados encriptados !
        try {
            if(boxCiphersuite == null){
                throw new IOException("Ciphersuite is invalid");
            }
            Cipher cipher = Cipher.getInstance(boxCiphersuite);
            if(boxIv == null) {
                throw new IOException("Iv is invalid");
            }
            IvParameterSpec ivSpec = new IvParameterSpec(boxIv.getBytes());
            if(boxKey == null) {
                throw new IOException("Key is invalid");
            }
            SecretKeySpec secretKey = new SecretKeySpec(boxKey.getBytes(), boxCiphersuite.split("/")[0]); // Necessário split? Testar!
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            int size = data.length;
            byte[] encryptedData;

            if(boxIntegrity != null) {
                int integritySize, ctLength;
                byte[] cipherText, integrityData;
                if(boxMackey == null) {
                    MessageDigest hash = MessageDigest.getInstance(boxIntegrity);
                    integritySize = hash.getDigestLength();

                    cipherText = new byte[cipher.getOutputSize(size + integritySize)];
                    ctLength = cipher.update(data, 0, size, cipherText, 0);

                    hash.update(data);
                    integrityData = hash.digest();
                }
                else {
                    Mac hMac = Mac.getInstance(boxIntegrity);
                    Key hMacKey = new SecretKeySpec(boxKey.getBytes(), boxMackey);
                    hMac.init(hMacKey);
                    integritySize = hMac.getMacLength();

                    cipherText = new byte[cipher.getOutputSize(size + integritySize)];
                    ctLength = cipher.update(data, 0, size, cipherText, 0);

                    hMac.update(data);
                    integrityData = hMac.doFinal();
                }
                cipher.doFinal(integrityData, 0, integritySize, cipherText, ctLength);
                // TODO: See if size has become to small (Fazer isto?)
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
        }
        catch (ShortBufferException e) {
            throw new IOException("Send Encrypted data has failed! Buffer is to short exception", e);
        }
    }

    public void receive(DatagramPacket p) throws IOException { // Decrypt
        byte[] data = decrypt(false, p.getData());
        if(data == null)
            return;

        // TODO: Fazer setLength() ?
        if(p.getLength() < data.length) {
            p.setLength(data.length);
            p.setData(data);
        }
        super.receive(p);
    }

    public byte[] decrypt(boolean isMovie, byte[] data) throws IOException {
        String ciphersuite, key, iv, integrity, mackey;
        if(isMovie) {
            ciphersuite = movieCiphersuite;
            key = movieKey;
            iv = movieIv;
            integrity = movieIntegrity;
            mackey = movieMackey;
        }
        else {
            ciphersuite = boxCiphersuite;
            key = boxKey;
            iv = boxIv;
            integrity = boxIntegrity;
            mackey = boxMackey;
        }

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
                        return movieData;
                    }
                    else { // Não mandar o packet! Integrity check failed!
                        return null;
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
                        return movieData;
                    }
                    else {  // Não mandar o packet! Integrity check failed!
                        return null;
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
    }
}
