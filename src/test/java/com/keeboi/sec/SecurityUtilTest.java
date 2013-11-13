/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.keeboi.sec;

import com.keeboi.libraries.security.Encryption;
import com.keeboi.libraries.security.Hash;
import com.keeboi.libraries.security.SecurityUtil;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 *
 * @author Kevin D. (https://github.com/akiwarheit)
 */
public class SecurityUtilTest extends TestCase {

    public SecurityUtilTest(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(SecurityUtilTest.class);
    }

    public void test() {
        SecretKey skey = SecurityUtil.getInstance().generateKey(Encryption.AES, 128);
        String message = "Hello world!";
        String encryptedMessage = SecurityUtil.getInstance().encrypt(skey, message, Encryption.AES);
        String decryptedMessage = SecurityUtil.getInstance().decrypt(skey, encryptedMessage, Encryption.AES);

        System.out.println(message);
        System.out.println(encryptedMessage);
        System.out.println(decryptedMessage);

        assertTrue(message.equals(decryptedMessage));
        try {
            String hashedMessage = new String(SecurityUtil.getInstance().hash(message, Hash.SHA1), "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(SecurityUtilTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
