package com.keeboi.libraries.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class SecurityUtil {

    public static class HashingAlgorithms {
        public static final String SHA_1 = "SHA-1";
        public static final String MD5 = "MD5";
    }

    public static class EncryptionAlgorithms {
        public static final String AES = "AES";
        public static final String DES = "DES";
    }

    public SecurityUtil() {
    }

    /**
     * Hash string, provided with hashing algorithm. (charset is set to UTF-8)
     * 
     * @param text
     * @param algorithm
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public byte[] hash(String text, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        digest.reset();
        byte[] input = digest.digest(text.getBytes("UTF-8"));

        return input;
    }

    /**
     * Hash string, provided with hashing algorithm and character set
     * 
     * @param text
     * @param algorithm
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public byte[] hash(String text, String algorithm, String charset) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        digest.reset();
        byte[] input = digest.digest(text.getBytes(charset));

        return input;
    }

    /**
     * 
     * @param hash
     * @return
     */
    public String encodeBase64(byte[] hash) {
        String base64encoded = Base64.encodeBase64String(hash);
        return base64encoded;
    }

    /**
     * 
     * @param text
     * @param algorithm
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public String hashEncode(String text, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] encoded = hash(text, algorithm);
        return Base64.encodeBase64String(encoded);
    }

    /**
     * 
     * @param string
     * @return
     */
    public String encryptSha256Base64(String string) {
        byte[] bytes = DigestUtils.sha256(string);
        String encryptedString = Base64.encodeBase64String(bytes);
        return encryptedString;
    }

    /**
     * 
     * @param sKey
     * @param plainText
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     */
    public String encrypt(SecretKey sKey, String plainText, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        StringEncrypter encrypter = new StringEncrypter(sKey, algorithm);
        String encrypted = encrypter.encrypt(plainText);
        return encrypted;
    }

    /**
     * 
     * @param sKey
     * @param encryptedString
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public String decrypt(SecretKey sKey, String encryptedString, String algorithm) throws IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        StringEncrypter encrypter = new StringEncrypter(sKey, algorithm);
        String decrypted = encrypter.decrypt(encryptedString);
        return decrypted;
    }

    /**
     * 
     * @param algorithm
     * @param bytes
     * @return
     * @throws NoSuchAlgorithmException
     */
    public SecretKey generateKey(String algorithm, int bytes) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(bytes);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey;
    }

    /**
     * 
     * @param secretKey
     * @return
     */
    public String convertSecretKeyToString(SecretKey secretKey) {
        byte[] encoded = secretKey.getEncoded();
        String data = Base64.encodeBase64String(encoded);
        return data;
    }

    /**
     * 
     * @param hex
     * @param algorithm
     * @return
     */
    public SecretKey loadKey(String hex, String algorithm) {
        byte[] encoded = Base64.decodeBase64(hex);
        SecretKey key = new SecretKeySpec(encoded, algorithm);
        return key;
    }

}
