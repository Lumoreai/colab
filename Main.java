package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) {
        try {
            // Read passphrase from file
            String passphrase = new String(Files.readAllBytes(Paths.get("Passphrase.txt")), StandardCharsets.UTF_8).trim();

            // Compute SHA-1 hash of the passphrase
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] sha1Hash = sha1.digest(passphrase.getBytes(StandardCharsets.UTF_8));

            // Print SHA-1 hash as a hex string
            System.out.println("SHA-1 Hash: " + bytesToHex(sha1Hash));

            // Extract first 16 bytes as AES key
            byte[] aesKey = Arrays.copyOfRange(sha1Hash, 0, 16);

            // Read encrypted file
            byte[] encryptedData = Files.readAllBytes(Paths.get("EncryptedData.data"));

            // Extract IV from the first 16 bytes
            byte[] iv = Arrays.copyOfRange(encryptedData, 0, 16);

            // Extract ciphertext (remaining bytes)
            byte[] cipherText = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);

            // Decrypt the ciphertext
            byte[] decryptedData = decryptAES_CBC(aesKey, iv, cipherText);

            // Write decrypted data to OriginalData.txt
            Files.write(Paths.get("OriginalData.txt"), decryptedData);
            System.out.println("Decryption successful! Decrypted data saved to OriginalData.txt");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] decryptAES_CBC(byte[] key, byte[] iv, byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(cipherText);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }
}