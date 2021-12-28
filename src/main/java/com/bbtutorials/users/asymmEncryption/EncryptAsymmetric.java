package com.bbtutorials.users.asymmEncryption;

import org.springframework.stereotype.Component;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

@Component
public class EncryptAsymmetric {

  public String encryptAsymmetric(String plaintext) throws IOException, GeneralSecurityException {
    // TODO(developer): Replace these variables before running the sample.
	  String projectId = "gcpcoe-333707";
	  String locationId = "global";
	  String keyRingId = "ring1";
	  String keyId = "test1-hsm-asymm";
	  String keyVersionId = "1";
//	  String plaintext = "Plaintext to encrypt";
//    encryptAsymmetric(projectId, locationId, keyRingId, keyId, keyVersionId, plaintext);
	  return encryptAsymmetric(projectId, locationId, keyRingId, keyId, keyVersionId, plaintext);
  }

  // Encrypt data that was encrypted using the public key component of the given
  // key version.
  public String encryptAsymmetric(
      String projectId,
      String locationId,
      String keyRingId,
      String keyId,
      String keyVersionId,
      String plaintext)
      throws IOException, GeneralSecurityException {
	  
	  byte[] ciphertext;
	  String encodedCiphertext;
	  
    // Initialize client that will be used to send requests. This client only
    // needs to be created once, and can be reused for multiple requests. After
    // completing all of your requests, call the "close" method on the client to
    // safely clean up any remaining background resources.
    try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
      // Build the key version name from the project, location, key ring, key,
      // and key version.
      CryptoKeyVersionName keyVersionName =
          CryptoKeyVersionName.of(projectId, locationId, keyRingId, keyId, keyVersionId);

      // Get the public key.
      PublicKey publicKey = client.getPublicKey(keyVersionName);

      // Convert the public PEM key to a DER key (see helper below).
      byte[] derKey = convertPemToDer(publicKey.getPem());
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);
      java.security.PublicKey rsaKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

      // Encrypt plaintext for the 'RSA_DECRYPT_OAEP_2048_SHA256' key.
      // For other key algorithms:
      // https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      OAEPParameterSpec oaepParams =
          new OAEPParameterSpec(
              "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
      cipher.init(Cipher.ENCRYPT_MODE, rsaKey, oaepParams);
      ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
//       System.out.println(ciphertext.length);
       
        encodedCiphertext = Base64.getEncoder().encodeToString(ciphertext);
//       byte[] decodedCiphertext = Base64.getDecoder().decode(encodedCiphertext);
       
//       System.out.println("enc" + encodedCiphertext + "\n " + encodedCiphertext.length());
       
//       for(int i =0; i<ciphertext.length; i++) {
//    	   System.out.print(ciphertext[i]+ " ");
//       }
       
//       System.out.println("\n");
       
//       for(int i =0; i<decodedCiphertext.length; i++) {
//    	   System.out.print(decodedCiphertext[i]+ " ");
//       }
       
//      System.out.printf("Ciphertext: %s%n", ciphertext + " / " + ciphertext.getClass());
//      System.out.println("Cyopheyr:"+ new String(ciphertext));
//      System.out.println(Arrays.equals(decodedCiphertext, ciphertext));
    }
//    return new String(ciphertext, StandardCharsets.UTF_8);
    return encodedCiphertext;
  }

  // Converts a base64-encoded PEM certificate like the one returned from Cloud
  // KMS into a DER formatted certificate for use with the Java APIs.
  private byte[] convertPemToDer(String pem) {
    BufferedReader bufferedReader = new BufferedReader(new StringReader(pem));
    String encoded =
        bufferedReader
            .lines()
            .filter(line -> !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
            .collect(Collectors.joining());
    return Base64.getDecoder().decode(encoded);
  }
}