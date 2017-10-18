package com.criptofields.example;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private static final int KEY_LENGTH = 2048;
    private KeyPair rsaKey;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String inputText = "Password";
        Log.d("TAGTAG", "Input text " + inputText);


        String encryptedText = sha(inputText);
        Log.d("TAGTAG", "Output text " + encryptedText);

        // GET KEY (GENERATE OR GET FROM CERTIFICATE
        this.rsaKey = RSAEncrypt.generateKey(KEY_LENGTH);

        //create an inputstream from a string
        try {
            ByteArrayInputStream plainTextInputStream =
                    new ByteArrayInputStream(inputText.getBytes("UTF-8"));

            //encrypt the combined keys using rsa and store the encrypted value
            byte[] encryptedAESKey = RSAEncrypt.encrypt(
                    inputText.getBytes(Charset.forName("UTF-8")),
                    this.rsaKey.getPublic());


            //set ui textview to encrypted base64 encoded value
            String encryptedString = new String(Base64.encode(encryptedAESKey, 0));


            Log.d("TAGTAG", "Output text encryptedString " + encryptedString);

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }

    public static String sha(String string) {
        if (TextUtils.isEmpty(string)) {
            return "";
        }
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("sha-256");
            byte[] bytes = md5.digest((string).getBytes());
            String result = "";
            for (byte b : bytes) {
                String temp = Integer.toHexString(b & 0xff);
                if (temp.length() == 1) {
                    temp = "0" + temp;
                }
                result += temp;
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }


    public String encryption(String strNormalText) {
        String seedValue = "YourSecKey";
        String normalTextEnc = "";
        try {
            normalTextEnc = AESHelper.encrypt(seedValue, strNormalText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return normalTextEnc;
    }

    public String decryption(String strEncryptedText) {
        String seedValue = "YourSecKey";
        String strDecryptedText = "";
        try {
            strDecryptedText = AESHelper.decrypt(seedValue, strEncryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strDecryptedText;
    }

    public SecretKey generateKey() throws NoSuchAlgorithmException {
        // Generate a 256-bit key
        final int outputKeyLength = 256;

        SecureRandom secureRandom = new SecureRandom();
        // Do *not* seed secureRandom! Automatically seeded from system entropy.
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(outputKeyLength, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

}
