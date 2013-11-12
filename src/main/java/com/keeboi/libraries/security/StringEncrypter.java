package com.keeboi.libraries.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Base64;

public class StringEncrypter {

    private Cipher eCipher;
    private Cipher dCipher;

    public StringEncrypter(SecretKey sKey, Encryption algorithm) throws NoSuchPaddingException, InvalidKeyException {
        try {
            String algo = "";
            switch (algorithm) {
                case AES:
                    algo = "AES";
                    break;
                case DES:
                    algo = "DES";
                    break;
                default:
                    algo = "AES";
                    break;
            }
            eCipher = Cipher.getInstance(algo);
            dCipher = Cipher.getInstance(algo);
            eCipher.init(Cipher.ENCRYPT_MODE, sKey);
            dCipher.init(Cipher.DECRYPT_MODE, sKey);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(StringEncrypter.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public String encrypt(String str) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] utf8 = str.getBytes("UTF8");
        byte[] enc = eCipher.doFinal(utf8);
        return Base64.encodeBase64String(enc);
    }

    public String encrypt(String str, String charset) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] utf8 = str.getBytes(charset);
        byte[] enc = eCipher.doFinal(utf8);
        return Base64.encodeBase64String(enc);
    }

    public String decrypt(String str) throws IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] dec = Base64.decodeBase64(str);
        byte[] utf8 = dCipher.doFinal(dec);
        return new String(utf8, "UTF8");
    }

    public String decrypt(String str, Charset charset) throws IOException, IllegalBlockSizeException, BadPaddingException {
        String chars = "";
        switch (charset) {
            case UTF8:
                chars = "UTF8";
                break;
        }
        byte[] dec = Base64.decodeBase64(str);
        byte[] utf8 = dCipher.doFinal(dec);
        return new String(utf8, chars);
    }
}
