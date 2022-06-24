package com.google.cose.utils;

import com.google.cose.exceptions.CoseException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CoseUtilsTest {
  @Test
  public void testECPublicKeyGenerationFromPrivateKey() throws NoSuchAlgorithmException,
      InvalidAlgorithmParameterException, CoseException {
    // generate ec2 key.
    ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(spec);
    KeyPair pair = generator.generateKeyPair();
    byte[] publicKeyBytes = pair.getPublic().getEncoded();
    // use private key to generate public key
    PublicKey publicKey = CoseUtils.getEc2PublicKeyFromPrivateKey(1,
        (ECPrivateKey) pair.getPrivate());
    // verify that the newly generated public key matches public key already present.
    Assert.assertArrayEquals(publicKeyBytes, publicKey.getEncoded());
  }
}
