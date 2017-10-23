package com.criptofields.example;

import android.content.Context;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private static final int KEY_LENGTH = 2048;
    private KeyPair rsaKey;

    private final static String PRIVATE_KEY =
            "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM7t8Ub1DP+B91NJ\n"
                    + "nC45zqIvd1QXkQ5Ac1EJl8mUglWFzUyFbhjSuF4mEjrcecwERfRummASbLoyeMXl\n"
                    + "eiPg7jvSaz2szpuV+afoUo9c1T+ORNUzq31NvM7IW6+4KhtttwbMq4wbbPpBfVXA\n"
                    + "IAhvnLnCp/VyY/npkkjAid4c7RoVAgMBAAECgYBcCuy6kj+g20+G5YQp756g95oN\n"
                    + "dpoYC8T/c9PnXz6GCgkik2tAcWJ+xlJviihG/lObgSL7vtZMEC02YXdtxBxTBNmd\n"
                    + "upkruOkL0ElIu4S8CUwD6It8oNnHFGcIhwXUbdpSCr1cx62A0jDcMVgneQ8vv6vB\n"
                    + "/YKlj2dD2SBq3aaCYQJBAOvc5NDyfrdMYYTY+jJBaj82JLtQ/6K1vFIwdxM0siRF\n"
                    + "UYqSRA7G8A4ga+GobTewgeN6URFwWKvWY8EGb3HTwFkCQQDgmKtjjJlX3BotgnGD\n"
                    + "gdxVgvfYG39BL2GnotSwUbjjce/yZBtrbcClfqrrOWWw7lPcX1d0v8o3hJfLF5dT\n"
                    + "6NAdAkA8qAQYUCSSUwxJM9u0DOqb8vqjSYNUftQ9dsVIpSai+UitEEx8WGDn4SKd\n"
                    + "V8kupy/gJlau22uSVYI148fJSCGRAkBz+GEHFiJX657YwPI8JWHQBcBUJl6fGggi\n"
                    + "t0F7ibceOkbbsjU2U4WV7sHyk8Cei3Fh6RkPf7i60gxPIe9RtHVBAkAnPQD+BmND\n"
                    + "By8q5f0Kwtxgo2+YkxGDP5bxDV6P1vd2C7U5/XxaN53Kc0G8zu9UlcwhZcQ5BljH\n"
                    + "N24cUWZOo+60\n";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // --------SIMPLE ENCRYPTION
        String inputText = "1234567890";
        Log.d("TAGTAG", "Input text " + inputText);

        String encryptedText = sha(inputText);
        Log.d("TAGTAG", "Output text " + encryptedText);

        //  ---------- RSA ENCRIPTING
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

        // ------------STRING TO PRIVATE KEY
        try {
            Context context = getApplicationContext();
            // Convert string to key object
            PrivateKey privateKey = stringToPrivateKey(PRIVATE_KEY);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);

            // cipher
            byte[] outputEncrypt = cipher.doFinal(inputText.getBytes());

            // Transform to string to send
            String encoded64 = Base64.encodeToString(outputEncrypt, 0);
            Log.d("TAGTAG","Encripting with private_key key: " + encoded64);


            // ------------ PUBLIC CRETIFICATE FROM FILE
            InputStream caInput = context.getResources().openRawResource(
                    context.getResources().getIdentifier("public_key",
                            "raw", context.getPackageName()));
            Certificate ca;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            ca = cf.generateCertificate(caInput);
            PublicKey publicKey = ca.getPublicKey();
            caInput.close();


            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            outputEncrypt = cipher.doFinal(inputText.getBytes());

            // Transform to string to send
            encoded64 = Base64.encodeToString(outputEncrypt, 0);
            Log.d("TAGTAG","Encripting with public_key file: " + encoded64);

            // DECRIPT WITH PRIVATE KEY
            // get private key file
            InputStream fis;
            fis = getResources().openRawResource(
                    getResources().getIdentifier("private_key",
                            "raw", getPackageName()));
            StringBuffer fileContent = new StringBuffer("");

            byte[] buffer = new byte[1024];

            int n;
            while ((n = fis.read(buffer)) != -1)
            {
                fileContent.append(new String(buffer, 0, n));
            }

            privateKey = stringToPrivateKey(fileContent.toString());

            // Transform to string to received
            byte[] dencoded64 = Base64.decode(encoded64, 0);

            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);



            // cipher
            byte[] decryptedBytes = cipher.doFinal(dencoded64);




            Log.d("TAGTAG","Decrypt with private KEY  " + new String(decryptedBytes,"UTF-8"));



        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

    }

    public PrivateKey stringToPrivateKey(String string) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read in the key into a String
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(string));
        String line;
        while ((line = rdr.readLine()) != null) {
            pkcs8Lines.append(line);
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replaceAll("-----BEGIN PRIVATE KEY-----","");
        pkcs8Pem = pkcs8Pem.replaceAll("-----END PRIVATE KEY-----","");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

        // Base64 decode the result

        byte [] pkcs8EncodedBytes = Base64.decode(pkcs8Pem, Base64.DEFAULT);

        // extract the private_key key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);


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

    public static String byteToHex(byte[] bytes) {

        String result = "";
        for (byte b : bytes) {
            String temp = Integer.toHexString(b & 0xff);
            if (temp.length() == 1) {
                temp = "0" + temp;
            }
            result += temp;
        }
        return result;
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
