package com.criptofields.example;

import android.util.Log;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
/**
 * KEY_TYPE_RSA Helper Encryption Class
 */
public class RSAEncrypt {

    public static final String KEY_TYPE_RSA = "RSA";

    public static KeyPair generateKey(int keylenght)
    {
        KeyPairGenerator keyPairGenerator = null;
        try
        {
            //get an KEY_TYPE_RSA key generator
            keyPairGenerator = KeyPairGenerator.getInstance(KEY_TYPE_RSA);
            //initialize the key to 2048 bits
            keyPairGenerator.initialize(keylenght);
            //return the generated key pair
            return keyPairGenerator.genKeyPair();
        }
        catch (NoSuchAlgorithmException e)
        {
            Log.d("TAGTAG", e.getMessage());
            return null;
        }
    }

    /**
     * main KEY_TYPE_RSA encrypt method
     *
     * @param plain     plain text you want to encrypt
     * @param publicKey public key to encrypt with
     * @return          encrypted text
     */
    public static byte[] encrypt(byte[] plain, PublicKey publicKey)
    {
        byte[] enc = null;
        try
        {
            Cipher cipher = Cipher.getInstance(KEY_TYPE_RSA);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            enc = cipher.doFinal(plain);
        }
        //no need to catch 4 different exceptions
        catch (Exception e)
        {
            Log.e(RSAEncrypt.class.getName(), e.getMessage(), e);
            throw new RuntimeException(e);
        }

        return enc;
    }

    /**
     *  main KEY_TYPE_RSA decrypt method
     *
     * @param enc           encrypted text you want to dcrypt
     * @param privateKey    private key to use for decryption
     * @return              plain text
     */
    public static byte[] decryptRSA(byte[] enc, PrivateKey privateKey)
    {
        byte[] plain = null;
        try
        {
            Cipher cipher = Cipher.getInstance(KEY_TYPE_RSA);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            plain = cipher.doFinal(enc);
        }
        //no need to catch 4 different exceptions
        catch (Exception e)
        {
            Log.e(RSAEncrypt.class.getName(), e.getMessage(), e);
            throw new RuntimeException(e);
        }
        return plain;
    }

}
