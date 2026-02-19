package com.google.cose.utils;

import com.google.cose.Ec2SigningKey;
import com.google.cose.Sign1Message;
import com.google.cose.exceptions.CoseException;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

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

  @Test
  public void testSign1WithDetachedPayload() throws CborException, CoseException {
    Ec2SigningKey key = Ec2SigningKey.generateKey(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256);
    byte[] detachedContent = "test".getBytes();
    Algorithm algorithm = Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256;
    Sign1Message coseSign1 = CoseUtils.generateCoseSign1(key, new Map(), new Map(), null, detachedContent, null, algorithm);

    assertNull(
      "COSE_Sign1 message with detached content shouldn't contain a message",
      coseSign1.getMessage()
    );

    // Signature verification should succeed when detached content is supplied
    CoseUtils.verifyCoseSign1Message(key, coseSign1, detachedContent, null, algorithm);

    assertThrows(
      "Signature verification should fail when Sign1Message doesn't contain payload and detached content is not provided",
      CoseException.class,
      () -> CoseUtils.verifyCoseSign1Message(key, coseSign1, null, null, algorithm)
    );
  }

  @Test
  public void testSign1WithAlgorithmHeader() throws CborException, CoseException {
    Ec2SigningKey key = Ec2SigningKey.generateKey(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256);
    Algorithm algorithm = Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256;
    Map protectedHeaders = new Map().put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM), algorithm.getCoseAlgorithmId());
    Sign1Message coseSign1 = CoseUtils.generateCoseSign1(key, protectedHeaders, new Map(), "test".getBytes(), null, null, algorithm);

    // Signature verification should succeed when no algorithm is passed
    CoseUtils.verifyCoseSign1Message(key, coseSign1, null, null, null);
  }
}