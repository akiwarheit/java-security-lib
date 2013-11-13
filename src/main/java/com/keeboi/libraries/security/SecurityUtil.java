package com.keeboi.libraries.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class SecurityUtil {

    private static SecurityUtil securityUtil;

    public static SecurityUtil getInstance() {
        if (securityUtil == null) {
            securityUtil = new SecurityUtil();
            return securityUtil;
        } else {
            return securityUtil;
        }
    }

    private SecurityUtil() {
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
    public byte[] hash(String text, Hash algorithm) {
        byte[] input = null;
        try {
            String algo = "";
            switch (algorithm) {
                case SHA1:
                    algo = "SHA-1";
                    break;
                case SHA256:
                    algo = "SHA-256";
                    break;
                case MD5:
                    algo = "MD5";
                    break;
                default:
                    break;
            }
            MessageDigest digest = MessageDigest.getInstance(algo);
            digest.reset();
            input = digest.digest(text.getBytes("UTF-8"));

        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        }

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
    public byte[] hash(String text, Hash algorithm, Charset charset) {
        byte[] input = null;
        try {
            String algo = "";
            switch (algorithm) {
                case SHA1:
                    algo = "SHA-1";
                    break;
                case SHA256:
                    algo = "SHA-256";
                    break;
                case MD5:
                    algo = "MD5";
                    break;
                default:
                    break;
            }
            String chars = "";
            switch (charset) {
                case UTF8:
                    chars = "UTF8";
                    break;
            }
            MessageDigest digest = MessageDigest.getInstance(algo);
            digest.reset();
            input = digest.digest(text.getBytes(chars));
            return input;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
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
    public String hashEncode(String text, Hash algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
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
     */
    public String encrypt(SecretKey sKey, String plainText, Encryption algorithm) {
        StringEncrypter encrypter;
        String encrypted = "";
        try {
            encrypter = new StringEncrypter(sKey, algorithm);
            encrypted = encrypter.encrypt(plainText);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return encrypted;
    }

    /**
     *
     * @param sKey
     * @param encryptedString
     * @return
     */
    public String decrypt(SecretKey sKey, String encryptedString, Encryption algorithm) {
        StringEncrypter encrypter;
        String decrypted = "";
        try {
            encrypter = new StringEncrypter(sKey, algorithm);
            decrypted = encrypter.decrypt(encryptedString);
        } catch (IOException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return decrypted;
    }

    /**
     *
     * @param sKey
     * @param encryptedString
     * @return
     */
    public String decrypt(SecretKey sKey, String encryptedString, Encryption algorithm, Charset charset) {
        StringEncrypter encrypter;
        String decrypted = "";
        try {
            encrypter = new StringEncrypter(sKey, algorithm);
            decrypted = encrypter.decrypt(encryptedString, charset);
        } catch (IOException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return decrypted;
    }

    /**
     *
     * @param algorithm
     * @param bytes
     * @return
     * @throws NoSuchAlgorithmException
     */
    public SecretKey generateKey(Encryption algorithm, int bytes) {
        KeyGenerator keyGen = null;
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
            keyGen = KeyGenerator.getInstance(algo);
            keyGen.init(bytes);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SecurityUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
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
