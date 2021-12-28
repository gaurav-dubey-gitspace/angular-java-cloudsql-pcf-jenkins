package com.bbtutorials.users.asymmEncryption;

import org.springframework.stereotype.Component;
import com.google.cloud.kms.v1.AsymmetricDecryptResponse;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.util.Base64;

@Component
public class DecryptAsymmetric {

  public String decryptAsymmetric(String encodedCiphertext) throws IOException {
    // TODO(developer): Replace these variables before running the sample.
    String projectId = "gcpcoe-333707";
    String locationId = "global";
    String keyRingId = "ring1";
    String keyId = "test1-hsm-asymm";
    String keyVersionId = "1";
    
//    byte[] ciphertextInBytes = cyphertext.getBytes();
    byte[] decodedCiphertext = Base64.getDecoder().decode(encodedCiphertext);
    return decryptAsymmetric(projectId, locationId, keyRingId, keyId, keyVersionId, decodedCiphertext);
  }

  // Decrypt data that was encrypted using the public key component of the given
  // key version.
  public String decryptAsymmetric(
      String projectId,
      String locationId,
      String keyRingId,
      String keyId,
      String keyVersionId,
      byte[] ciphertext)
      throws IOException {
	  
	  String plaintext=null;
    // Initialize client that will be used to send requests. This client only
    // needs to be created once, and can be reused for multiple requests. After
    // completing all of your requests, call the "close" method on the client to
    // safely clean up any remaining background resources.
    try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
      // Build the key version name from the project, location, key ring, key,
      // and key version.
      CryptoKeyVersionName keyVersionName =
          CryptoKeyVersionName.of(projectId, locationId, keyRingId, keyId, keyVersionId);

      // Decrypt the ciphertext.
      AsymmetricDecryptResponse response =
          client.asymmetricDecrypt(keyVersionName, ByteString.copyFrom(ciphertext));
      System.out.printf("Plaintext: %s%n", response.getPlaintext().toStringUtf8());
      plaintext= response.getPlaintext().toStringUtf8();
    }
	return plaintext;
  }
}