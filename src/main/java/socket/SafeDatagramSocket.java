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

public class SafeDatagramSocket extends DatagramSocket {

    Cipher cipher;
    Properties properties;

    public SafeDatagramSocket() throws SocketException {
        super();
    }

    public SafeDatagramSocket(SocketAddress addr, String config) throws IOException {
        super();
        initBox(addr, config);
    }

    public SafeDatagramSocket(InetSocketAddress addr, String boxConfig) throws IOException {
        super();
        initServer(addr, boxConfig);
    }

    private void initServer(InetSocketAddress addr, String boxConfig) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        properties = readProperies(boxConfig, addr.toString());
        cipher = CryptoStuff.readProps(properties, Cipher.ENCRYPT_MODE);
    }

    private void initBox(SocketAddress addr, String config) throws IOException {
        properties = readProperies(config, addr.toString());
        cipher = CryptoStuff.readProps(properties, Cipher.DECRYPT_MODE);
    }

    private Properties readProperies(String path, String target) {
        String propsFileName;
        Properties properties = null;
        try {
            propsFileName = ConfigReader.read(path, target.split("/")[1]);
            InputStream inputStream = new FileInputStream(ConfigReader.CONFIG_PATH + propsFileName);
            properties = new Properties();
            properties.load(inputStream);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return properties;

    }

    public void send(DatagramPacket p) throws IOException { // Encrypt
        byte[] cipherText = p.getData();
        try {
        cipherText = CryptoStuff.encrypt(cipherText, cipher);
        } catch (Exception e) {
        e.printStackTrace();
        }
        p.setData(cipherText);
        super.send(p);

    }

    public void sendEncrypt(DatagramPacket p) throws IOException { // Decrypt
        byte[] movieData = p.getData();
        try {
            movieData = CryptoStuff.decrypt(movieData, cipher);
        } catch (Exception e) {
            e.printStackTrace();
        }
        p.setData(movieData);
        super.send(p);
    }

}
