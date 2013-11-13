Luisa's Security Library
=================

Some hashing and encryption helpers and stuff

Typical Usage
=================

1.  Encrypting and decrypting


    SecretKey skey = SecurityUtil.getInstance().generateKey(Encryption.AES, 128);
    String message = "Hello world!";
    String encryptedMessage = SecurityUtil.getInstance().encrypt(skey, message, Encryption.AES);
    String decryptedMessage = SecurityUtil.getInstance().decrypt(skey, encryptedMessage, Encryption.AES);

To be continued...
    
