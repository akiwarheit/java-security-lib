Luisa's Security Library
=================
Encryption library; it's so secure, promise.

Typical Usage
=================

1.  Encrypting and decrypting


        SecretKey skey = SecurityUtil.getInstance().generateKey(Encryption.AES, 128);
        String message = "Hello world!";
        String encryptedMessage = SecurityUtil.getInstance().encrypt(skey, message, Encryption.AES);
        String decryptedMessage = SecurityUtil.getInstance().decrypt(skey, encryptedMessage, Encryption.AES);
        assertTrue(message.equals(decryptedMessage)); // true dat

To be continued... (hashing is not yet done)
    
