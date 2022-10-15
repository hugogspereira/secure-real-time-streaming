package socket;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import util.Utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
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
            // TODO: Adicionar integrity check -> Hash ou HMACS !!!
            byte[] data = cipher.doFinal(p.getData());
            // TODO: Verificar se com o padding e/ou com o HASH o tamanho do buff não ficou maior do que o tamanho do buffer
            if(size < data.length) {
                p.setLength((int) Math.ceil((double) data.length/1024));
            }
            p.setData(data);
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
            // TODO: VERIFICAR o integrity check -> Hash ou HMACS !!!
            byte[] data = cipher.doFinal(p.getData());
            // TODO: Verificar se com o padding e/ou com o HASH o tamanho do buff não ficou maior do que o tamanho do buffer
            if(size < data.length) {
                p.setLength((int) Math.ceil((double) data.length/1024));
            }
            p.setData(data);
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
