package com.keeboi.libraries.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class StringEncrypter {

    private Cipher eCipher;
    private Cipher dCipher;

    public StringEncrypter(SecretKey sKey, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        eCipher = Cipher.getInstance(algorithm);
        dCipher = Cipher.getInstance(algorithm);
        eCipher.init(Cipher.ENCRYPT_MODE, sKey);
        dCipher.init(Cipher.DECRYPT_MODE, sKey);
    }

    public String encrypt(String str) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] utf8 = str.getBytes("UTF8");
        byte[] enc = eCipher.doFinal(utf8);
        return new sun.misc.BASE64Encoder().encode(enc);
    }
    
    public String encrypt(String str, String charset) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] utf8 = str.getBytes(charset);
        byte[] enc = eCipher.doFinal(utf8);
        return new sun.misc.BASE64Encoder().encode(enc);
    }

    public String decrypt(String str) throws IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);
        byte[] utf8 = dCipher.doFinal(dec);
        return new String(utf8, "UTF8");
    }

    public String decrypt(String str, String charset) throws IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);
        byte[] utf8 = dCipher.doFinal(dec);
        return new String(utf8, charset);
    }
}
