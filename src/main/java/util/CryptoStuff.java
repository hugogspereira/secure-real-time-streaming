package util;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Properties;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;

public class CryptoStuff {

    private static final String CIPHERSUITE = "CIPHERSUITE";
    private static final String KEY = "KEY";
    private static final String IV = "IV";
    private static final String INTEGRITY = "INTEGRITY";
    private static final String MACKEY = "MACKEY";

    public static byte[] encrypt(byte[] data, Cipher cipher) throws Exception {
        return doCrypto(cipher, data);
    }

    public static byte[] decrypt(byte[] data, Cipher cipher) throws Exception {
        return doCrypto(cipher, data);
    }

    private static byte[] doCrypto(Cipher cipher, byte[] data) throws IOException {

        byte[] cipherdata;
        try {
            cipherdata = cipher.doFinal(data);
        } catch (BadPaddingException e) {
            throw new IOException("Encript/Decript data has failed! Bad padding exception", e);
        } catch (IllegalBlockSizeException e) {
            throw new IOException("Encript/Decript data has failed! Illegal block size exception", e);
        }

        return cipherdata;

    }

    public static Cipher readProps(Properties props, int cipherMode) throws IOException {
        String ciphersuit = checkProperty(props, CIPHERSUITE);
        String key = checkProperty(props, KEY);
        String iv = checkProperty(props, IV);
        String integrity = checkProperty(props, INTEGRITY);
        String mackey = checkProperty(props, MACKEY);

        Security.addProvider(new BouncyCastlePQCProvider());

        try {
            
            if (ciphersuit == null) {
                throw new IOException("Ciphersuite is invalid");
            }
            Cipher cipher = Cipher.getInstance(ciphersuit);
            
            if (iv == null) {
                throw new IOException("Iv is invalid");
            }
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
            
            if (key == null) {
                throw new IOException("Key is invalid");
            }
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ciphersuit.split("/")[0]);
            
            cipher.init(cipherMode, secretKey, ivSpec);
            return cipher;

        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Encript/Decript data has failed! No such algorithm exception", e);
        } catch (NoSuchPaddingException e) {
            throw new IOException("Encript/Decript data has failed! No such padding exception", e);
        // } catch (NoSuchProviderException e) {
        //     throw new IOException("Encript/Decript data has failed! No such provider exception");
        } catch (InvalidKeyException e) {
            throw new IOException("Encript/Decript data has failed! Invalid key exception", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IOException("Encript/Decript data has failed! Invalid algorithm parameter exception", e);
        }

    }

    private static String checkProperty(Properties properties, String property) {
        String res = properties.getProperty(property);
        if (res.equalsIgnoreCase("NULL")) {
            res = null;
        }
        return res;
    }
}
