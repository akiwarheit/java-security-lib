/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.keeboi.sec;

import com.keeboi.libraries.security.Encryption;
import com.keeboi.libraries.security.SecurityUtil;
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
        SecretKey skey = SecurityUtil.generateKey(Encryption.AES, 128);
        String message = "Hello world!";
        String encryptedMessage = SecurityUtil.encrypt(skey, message, Encryption.AES);
        String decryptedMessage = SecurityUtil.decrypt(skey, encryptedMessage, Encryption.AES);

        System.out.println(message);
        System.out.println(encryptedMessage);
        System.out.println(decryptedMessage);

        assertTrue(message.equals(decryptedMessage));
    }
}
