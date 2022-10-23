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
import util.PrintStats;

public class SafeDatagramSocket {

    private static final String CIPHERSUITE = "CIPHERSUITE";
    private static final String KEY = "KEY";
    private static final String IV = "IV";
    private static final String INTEGRITY = "INTEGRITY";
    private static final String MACKEY = "MACKEY";
    public static final byte[] CONTROL_MESSAGE = new byte[1];

    private String boxCiphersuite, boxKey, boxIv, boxIntegrity, boxMackey, addr;
    private Cipher cipher;
    private DatagramSocket datagramSocket;

    public SafeDatagramSocket(SocketAddress addr, String config, String password) throws SocketException {
        this.datagramSocket = new DatagramSocket();
        readProperties(addr, config, password);
    }

    public SafeDatagramSocket(InetSocketAddress addr, String boxConfig, String password) throws SocketException {
        this.datagramSocket = new DatagramSocket();
        readProperties(addr, boxConfig, password);
    }

    private void readProperties(SocketAddress addr, String boxConfig, String password) throws SocketException {
        Security.addProvider(new BouncyCastleProvider());

        try {
            InputStream inputStream = new ByteArrayInputStream(ConfigReader.read(boxConfig, addr.toString().split("/")[1], password).toByteArray());
            if (inputStream == null) {
                System.err.println("Configuration Box file not found!");
                System.exit(1);
            }
            Properties properties = new Properties();
            properties.load(inputStream);

            this.boxCiphersuite = checkProperty(properties,CIPHERSUITE);
            this.cipher = Cipher.getInstance(boxCiphersuite);
            this.boxKey = checkProperty(properties,KEY);
            this.boxIv = checkProperty(properties,IV);
            this.boxIntegrity = checkProperty(properties,INTEGRITY);
            this.boxMackey = checkProperty(properties,MACKEY);
            this.addr = addr.toString();

            /*
            System.out.println(boxCiphersuite);
            System.out.println(boxKey);
            System.out.println(boxIv);
            System.out.println(boxIntegrity);
            System.out.println(boxMackey);
            System.out.println("-----------------");
            */
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

    public DatagramPacket encrypt(DatagramPacket p) throws IOException {   // Encrypt
        try {
            byte[] data = p.getData();
            if(boxCiphersuite == null){
                throw new IOException("Ciphersuite is invalid");
            }
            String[] transformation= boxCiphersuite.split("/");
            String mode = null;
            if(transformation.length > 1) {
                mode = transformation[1];
            }
            if(boxIv == null) {
                throw new IOException("Iv is invalid");
            }
            if(mode != null && mode.equalsIgnoreCase("CCM")) {
                if(boxIv.getBytes().length < 7 || boxIv.getBytes().length > 13) {
                    throw new IOException("With CCM mode the iv should be between 7 and 13 bytes");
                }
                else if(boxMackey == null) {
                    throw new IOException("With CCM mode the mac is necessary");
                }
            }
            IvParameterSpec ivSpec = new IvParameterSpec(boxIv.getBytes());

            if(boxKey == null) {
                throw new IOException("Key is invalid");
            }
            SecretKey secretKey = new SecretKeySpec(boxKey.getBytes(), 0, boxKey.getBytes().length, boxCiphersuite.split("/")[0]);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            int size = data.length;
            int integritySize, ctLength;
            byte[] cipherText, integrityData;

            if(boxIntegrity != null) {
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

                p.setData(cipherText);
                p.setLength(cipherText.length);
                return p;
            }
            else if((mode != null && mode.equalsIgnoreCase("GCM")) || (transformation[0].equalsIgnoreCase("ChaCha20-Poly1305"))) {
                cipherText = cipher.doFinal(data);
                p.setData(cipherText);
                p.setLength(cipherText.length);
                return p;
            }
            else {
                throw new IOException("Not defined the integrity control in config file!");
            }
        }
        catch (NoSuchAlgorithmException e) {
            throw new IOException("Send Encrypted data has failed! No such algorithm exception", e);
        }
        catch (InvalidKeyException e) {
            throw new IOException("Send Encrypted data has failed! Invalid key exception", e);
        }
        catch (InvalidAlgorithmParameterException e) {
            throw new IOException("Send Encrypted data has failed! Invalid algorithm parameter exception", e);
        }
        catch (IllegalBlockSizeException e) {
            throw new IOException(e);
        }
        catch (BadPaddingException e) {
            throw new IOException(e);
        }
        catch (IOException e) {
            throw new IOException(e);
        }
        catch (ShortBufferException e) {
            throw new IOException(e);
        }
    }

    public DatagramPacket decrypt(DatagramPacket p) throws IOException { // Decrypt
        try {
            byte[] movieData, data = p.getData();
            if(boxCiphersuite == null){
                throw new IOException("Ciphersuite is invalid");
            }
            String[] transformation= boxCiphersuite.split("/");
            String mode = null;
            if(transformation.length > 1) {
                mode = transformation[1];
            }
            if(boxIv == null) {
                throw new IOException("Iv is invalid");
            }
            IvParameterSpec ivSpec = new IvParameterSpec(boxIv.getBytes());
            if(boxKey == null) {
                throw new IOException("Key is invalid");
            }
            SecretKey secretKey = new SecretKeySpec(boxKey.getBytes(), 0, boxKey.getBytes().length, boxCiphersuite.split("/")[0]);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            int size = p.getLength();
            byte[] decryptedData, messageIntegrity;
            int messageLength;

            if(boxIntegrity != null) {
                if (boxMackey == null) {
                    MessageDigest hash = MessageDigest.getInstance(boxIntegrity);

                    decryptedData = cipher.doFinal(data, 0, size);
                    messageLength = decryptedData.length - hash.getDigestLength();
                    movieData = new byte[messageLength];
                    hash.update(decryptedData, 0, messageLength);

                    messageIntegrity = new byte[hash.getDigestLength()];
                    System.arraycopy(decryptedData, messageLength, messageIntegrity, 0, messageIntegrity.length);

                    if (MessageDigest.isEqual(hash.digest(), messageIntegrity)) {
                        System.arraycopy(decryptedData, 0, movieData, 0, messageLength);
                    }
                    else {
                        // TODO
                        System.out.println("ERROR 230");
                    }
                }
                else {
                    Mac hMac = Mac.getInstance(boxIntegrity);
                    Key hMacKey = new SecretKeySpec(boxKey.getBytes(), boxMackey);

                    decryptedData = cipher.doFinal(data, 0, size);
                    messageLength = decryptedData.length - hMac.getMacLength();
                    movieData = new byte[messageLength];

                    hMac.init(hMacKey);
                    hMac.update(decryptedData, 0, messageLength);

                    messageIntegrity = new byte[hMac.getMacLength()];
                    System.arraycopy(decryptedData, messageLength, messageIntegrity, 0, messageIntegrity.length);

                    if (MessageDigest.isEqual(hMac.doFinal(), messageIntegrity)) {
                        System.arraycopy(decryptedData, 0, movieData, 0, messageLength);
                    }
                    else {
                        // TODO
                        System.out.println("ERROR 251");
                    }
                }
                p.setData(movieData);
                p.setLength(movieData.length);
                return p;
            }
            else if((mode != null && mode.equalsIgnoreCase("GCM")) || (transformation[0].equalsIgnoreCase("ChaCha20-Poly1305"))) {
                decryptedData = cipher.doFinal(data, 0, size);
                p.setData(decryptedData);
                p.setLength(decryptedData.length);
                return p;
            }
            else {
                throw new IOException("Not defined the integrity control in config file!");
            }
        }
        catch (NoSuchAlgorithmException e) {
            throw new IOException("Receive Encrypted data has failed! No such algorithm exception", e);
        }
        catch (InvalidKeyException e) {
            throw new IOException("Receive Encrypted data has failed! Invalid key exception", e);
        }
        catch (InvalidAlgorithmParameterException e) {
            throw new IOException("Receive Encrypted data has failed! Invalid algorithm parameter exception", e);
        }
        catch (IllegalBlockSizeException e) {
            throw new IOException(e);
        }
        catch (BadPaddingException e) {
            throw new IOException(e);
        }
        catch (IOException e) {
            throw new IOException(e);
        }
    }

    public void send(DatagramPacket p, SocketAddress addr) throws IOException {
        p.setSocketAddress(addr);
        datagramSocket.send(p);
    }

    public void send(DatagramPacket p) throws IOException {
        datagramSocket.send(p);
    }

    public void printBoxConfigStatus() {
        PrintStats.toPrintBoxConfigStats(addr, boxCiphersuite, boxKey, boxKey.length(), boxIntegrity);
    }

    public void printServerConfigStatus() {
        PrintStats.toPrintServerConfigStats(addr, boxCiphersuite, boxKey, boxKey.length(), boxIntegrity);
    }

}
