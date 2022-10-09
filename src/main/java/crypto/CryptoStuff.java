package crypto;
/**
 ** A utility class that encrypts or decrypts a file.
 ** Version 2
**/


// This is version 2 of CryptoStuff class (ex 3, Lab 1)
// In this version we separate the definition of ALGORITHM
// and the definition of CIPHERSUITE parameterization to be
// more clear and correct the utilization and generalization of
// use ...

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoStuff
{
   
     private static final String ALGORITHM = "AES";
     private static final String TRANSFORMATION = "AES/CTR/NoPadding";
     private static final byte[] ivBytes  = new byte[]
     {
	    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,
        0x0f, 0x0d, 0x0e, 0x0c, 0x0b, 0x0a, 0x09, 0x08
     };

    
     public static byte[] encrypt(SecretKey key, byte[] data) throws Exception
     {
        return doCrypto(Cipher.ENCRYPT_MODE, key, data);
     }

    public static byte[] decrypt(SecretKey key, byte[] data) throws Exception
    {
        return doCrypto(Cipher.DECRYPT_MODE, key, data);
    }
    
     private static byte[] doCrypto(int cipherMode, SecretKey key, byte[] data) throws Exception
     {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            SecretKeySpec secretKey = new SecretKeySpec(key.getEncoded(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, secretKey, ivSpec);
            return cipher.doFinal(data);
        }
 	    catch (NoSuchPaddingException | NoSuchAlgorithmException
               | InvalidKeyException | BadPaddingException
               | IllegalBlockSizeException
               | InvalidAlgorithmParameterException ex)
	    {
	        throw new Exception("Error encrypting/decrypting data", ex);
	    }
	
     }
   
}
