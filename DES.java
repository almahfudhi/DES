import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class DES {
    static Cipher cipher;

    public DES() throws Exception {
        cipher = Cipher.getInstance("DES");

    }

    public String encrypt(String plainText, SecretKey secretKey) throws Exception {

        // Convert plaintext into byte representation
        byte[] plainTextByte = plainText.getBytes();

        // Initialise the cipher to be in encrypt mode, using the given key.
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Perform the encryption
        byte[] encryptedByte = cipher.doFinal(plainTextByte);

        // Get a new Base64 (ASCII) encoder and use it to convert ciphertext back to a
        // string
        Base64.Encoder encoder = Base64.getEncoder();
        String encryptedText = encoder.encodeToString(encryptedByte);

        return encryptedText;
    }

    public String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        // Get a new Base64 (ASCII) decoder and use it to convert ciphertext from a
        // string into bytes
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(encryptedText);

        // Initialise the cipher to be in decryption mode, using the given key.
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Perform the decryption
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);

        // Convert byte representation of plaintext into a string
        String decryptedText = new String(decryptedByte);

        return decryptedText;
    }

    public SecretKey generateRandomKey() throws NoSuchAlgorithmException {
        // Use java's key generator to produce a random key.
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        SecretKey secretKey = keyGenerator.generateKey();

        // print the key
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println(encodedKey);

        return secretKey;
    }

    public SecretKey generateKeyFromPassword(String password) throws Exception {

        // Get byte representation of password.
        // Note here you should ideally also use salt!
        byte[] passwordInBytes = (password).getBytes("UTF-8");

        // Use sha to generate a message digest of the password
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] key = sha.digest(passwordInBytes);

        // DES keys are only 128bits (16 bytes) so take first 128 bits of digest.
        key = Arrays.copyOf(key, 8);

        // Generate secret key using
        SecretKeySpec secretKey = new SecretKeySpec(key, "DES");

        // print the key
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println(encodedKey);

        return secretKey;
    }

    public static void main(String[] args) throws Exception {

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter plaintext:");

        String plaintext = scanner.nextLine(); // Read user input
        System.out.println("plaintext is: " + plaintext); // Output user input

        System.out.print("Enter password:");

        String key = scanner.nextLine(); // Read user input
        System.out.println("password is: " + key); // Output user input

        DES des = new DES();
        System.out.println("key 1 is:");
        SecretKey GeneratedFromPass = des.generateKeyFromPassword(key);
        String encrypted = des.encrypt(plaintext, GeneratedFromPass);
        System.out.println("encrypted using key GeneratedFromPass: " + encrypted);

        String decrypt = des.decrypt(encrypted, GeneratedFromPass);
        System.out.println("Decrypted using GeneratedFromPass: " + decrypt);

        System.out.println("Ramdom key is:");
        SecretKey randomekey = des.generateRandomKey();
        String encrypted2 = des.encrypt(plaintext, randomekey);
        System.out.println("encrypted using randomekey: " + encrypted2);
        String decrypt2 = des.decrypt(encrypted2, randomekey);
        System.out.println("Decrypted using randomekey: " + decrypt2);

        System.out.println("-- end--");

    }

}