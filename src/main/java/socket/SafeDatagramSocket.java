package socket;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import util.ConfigReader;
import util.CryptoStuff;

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

    private String addr;
    private Cipher cipher;
    Properties properties;
    private DatagramSocket datagramSocket;

    public SafeDatagramSocket(SocketAddress addr, String config, String password) throws IOException {
        
        this.datagramSocket = new DatagramSocket();
        
        readProperties(addr, config, password, Cipher.DECRYPT_MODE);
    }

    public SafeDatagramSocket(InetSocketAddress addr, String boxConfig, String password) throws IOException {
        if(addr.getAddress().isMulticastAddress()){
            MulticastSocket datagramSocket = new MulticastSocket(addr.getPort());
            datagramSocket.joinGroup(addr, null); 
            this.datagramSocket = datagramSocket;
        }
        else 
            this.datagramSocket = new DatagramSocket();

        readProperties(addr, boxConfig, password, Cipher.ENCRYPT_MODE);
    }

    private void readProperties(SocketAddress addr, String boxConfig, String password, int cipherMode)
            throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        try {
            InputStream inputStream = new ByteArrayInputStream(
                    ConfigReader.read(boxConfig, addr.toString().split("/")[1], password).toByteArray());
            if (inputStream == null) {
                System.err.println("Configuration Box file not found!");
                System.exit(1);
            }
            properties = new Properties();
            properties.load(inputStream);

            String boxCiphersuite = checkProperty(properties, CIPHERSUITE);
            this.cipher = Cipher.getInstance(boxCiphersuite);
            String boxKey = checkProperty(properties, KEY);
            String boxIv = checkProperty(properties, IV);
            String boxMackey = checkProperty(properties, MACKEY);

            if (boxCiphersuite == null) {
                throw new IOException("Ciphersuite is invalid");
            }
            String[] transformation = boxCiphersuite.split("/");
            String mode = null;
            if (transformation.length > 1) {
                mode = transformation[1];
            }
            if (boxIv == null) {
                throw new IOException("Iv is invalid");
            }
            if (mode != null && mode.equalsIgnoreCase("CCM")) {
                if (boxIv.getBytes().length < 7 || boxIv.getBytes().length > 13) {
                    throw new IOException("With CCM mode the iv should be between 7 and 13 bytes");
                } else if (boxMackey == null) {
                    throw new IOException("With CCM mode the mac is necessary");
                }
            }
            IvParameterSpec ivSpec = new IvParameterSpec(boxIv.getBytes());

            if (boxKey == null) {
                throw new IOException("Key is invalid");
            }
            SecretKey secretKey = new SecretKeySpec(boxKey.getBytes(), 0, boxKey.getBytes().length,
                    boxCiphersuite.split("/")[0]);
            cipher.init(cipherMode, secretKey, ivSpec);

            this.addr = addr.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Send Encrypted data has failed! No such algorithm exception", e);
        } catch (InvalidKeyException e) {
            throw new IOException("Send Encrypted data has failed! Invalid key exception", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IOException("Send Encrypted data has failed! Invalid algorithm parameter exception", e);
        } catch (IllegalBlockSizeException e) {
            throw new IOException(e);
        } catch (BadPaddingException e) {
            throw new IOException(e);
        } catch (IOException e) {
            throw new IOException(e);
        } catch (ShortBufferException e) {
            throw new IOException(e);
        } catch (Exception e) {
            e.printStackTrace();
            throw new SocketException(e.getMessage());
        }
    }

    private String checkProperty(Properties properties, String property) {
        String res = properties.getProperty(property);
        if (res.equalsIgnoreCase("NULL")) {
            res = null;
        }
        return res;
    }

    public DatagramPacket encrypt(DatagramPacket p) throws IOException { // Encrypt
        byte[] data = p.getData();

        int size = data.length;
        byte[] cipherText = CryptoStuff.encrypt(data, size, cipher, properties);

        p.setData(cipherText);
        p.setLength(cipherText.length);
        return p;

    }

    public DatagramPacket decrypt(DatagramPacket p) throws IOException { // Decrypt
        byte[] movieData, data = p.getData();

        int size = p.getLength();

        movieData = CryptoStuff.decrypt(data, size, cipher, properties);

        p.setData(movieData);
        p.setLength(movieData.length);
        return p;

    }

    public void send(DatagramPacket p, SocketAddress addr) throws IOException {
        p.setSocketAddress(addr);
        datagramSocket.send(p);
    }

    public void send(DatagramPacket p) throws IOException {
        datagramSocket.send(p);
    }

    public void printBoxConfigStatus() {
        String boxKey = checkProperty(properties, KEY);
        String boxIntegrity = checkProperty(properties, INTEGRITY);
        if (boxIntegrity == null)
            boxIntegrity = checkProperty(properties, MACKEY);
        PrintStats.toPrintBoxConfigStats(addr, checkProperty(properties, CIPHERSUITE), boxKey, boxKey.length(),
                boxIntegrity);
    }

    public void printServerConfigStatus() {
        String boxKey = checkProperty(properties, KEY);
        String boxIntegrity = checkProperty(properties, INTEGRITY);
        if (boxIntegrity == null)
            boxIntegrity = checkProperty(properties, MACKEY);
        PrintStats.toPrintServerConfigStats(addr, checkProperty(properties, CIPHERSUITE), boxKey, boxKey.length(),
                boxIntegrity);
    }

}
