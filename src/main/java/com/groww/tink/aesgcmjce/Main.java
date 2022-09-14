/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */

import java.security.GeneralSecurityException;
import java.util.Base64;

import com.groww.crypto.customaesjcm.AesGcmJce;

public class Main {

    public static void main(String[] args)
            throws GeneralSecurityException {

        String plainText = "JUST Try This";
        String aad = "";
        String key = "1234567890123456";
          // Change Key and Plain Text  Key Format could be 128bit AES Key
        // Encryption
        AesGcmJce aesGcmJce = new AesGcmJce(key.getBytes());
        byte[] encrypted = aesGcmJce.encrypt(plainText.getBytes(), aad.getBytes());
        System.out.println(new String(encrypted));
        String encryptedBase64 = Base64.getEncoder()
                .encodeToString(encrypted);
        byte[] decrypted64key = Base64.getDecoder()
                .decode(encryptedBase64);
        System.out.println(encryptedBase64);

        // Decryption
        AesGcmJce agjDecryption = new AesGcmJce(key.getBytes());
        byte[] decrypted = agjDecryption.decrypt(decrypted64key, aad.getBytes());
        System.out.println(new String(decrypted));

    }


}