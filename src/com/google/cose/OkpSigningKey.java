/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.cose;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Sign.KeyPair;
import com.google.crypto.tink.subtle.Ed25519Verify;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Implements OKP COSE_Key spec for signing purposes.
 * Currently only supports Ed25519 curve.
 */
public final class OkpSigningKey extends OkpKey {
  public OkpSigningKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);

    int curve = CborUtils.asInteger(labels.get(Headers.KEY_PARAMETER_CURVE));
    if (curve != Headers.CURVE_OKP_ED25519) {
      throw new CoseException(CoseException.UNSUPPORTED_CURVE_EXCEPTION_MESSAGE);
    }

    if ((operations != null)
        && !operations.contains(Headers.KEY_OPERATIONS_VERIFY)
        && !operations.contains(Headers.KEY_OPERATIONS_SIGN)) {
      throw new CoseException("Signing key requires either sign or verify operation.");
    }
  }

  public static OkpSigningKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static OkpSigningKey decode(DataItem cborKey) throws CborException, CoseException {
    return new OkpSigningKey(cborKey);
  }

  @Override
  protected byte[] publicFromPrivate(byte[] privateKey) throws CoseException {
    try {
      return KeyPair.newKeyPairFromSeed(privateKeyBytes).getPublicKey();
    } catch (GeneralSecurityException e) {
      throw new CoseException("Error while generating public key from private key bytes.", e);
    }
  }

  @Override
  public PublicKey getPublicKey() throws CoseException {
    try {
      // Ed25519 support was added to Java 15 with the EdECPublicKeySpec but, in order to support
      // older versions, generate the key with an x509EncodedKeySpec with an encoded key as
      // defined in rfc8410. Before Java 15, a security provider that can handle Ed25519 keys needs
      // to be installed.
      byte[] subjectPublicKeyInfo =
          new byte[] {
            0x30, 0x2a,                    // SEQUENCE
            0x30, 0x05,                    //   SEQUENCE
            0x06, 0x03, 0x2b, 0x65, 0x70,  //     OBJECT IDENTIFIER { 1 3 101 112 }
            0x03, 0x21, 0x00,              //     BIT STRING
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          };
      System.arraycopy(publicKeyBytes, 0, subjectPublicKeyInfo, 12, 32);
      X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo);
      return KeyFactory.getInstance("Ed25519").generatePublic(x509EncodedKeySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new CoseException("Failed to generate Ed25519 public key", e);
    }
  }

  /** Generates a COSE formatted OKP signing key from scratch */
  public static OkpSigningKey generateKey() throws CborException, CoseException {
    return builder()
        .withGeneratedKeyPair(Headers.CURVE_OKP_ED25519)
        .withAlgorithm(Algorithm.SIGNING_ALGORITHM_EDDSA)
        .build();
  }

  public static class Builder extends OkpKey.Builder<Builder> {
    @Override
    public Builder self() {
      return this;
    }

    @Override
    public Builder withOperations(Integer...operations) throws CoseException {
      for (int operation : operations) {
        if (operation != Headers.KEY_OPERATIONS_SIGN
            && operation != Headers.KEY_OPERATIONS_VERIFY) {
          throw new CoseException("Signing key only supports Sign or Verify operations.");
        }
      }
      return super.withOperations(operations);
    }

    @Override
    public OkpSigningKey build() throws CborException, CoseException {
      withCurve(Headers.CURVE_OKP_ED25519);
      return new OkpSigningKey(compile());
    }

    public Builder withGeneratedKeyPair(int curve) throws CoseException {
      if (curve != Headers.CURVE_OKP_ED25519) {
        throw new CoseException("Unsupported curve: " + curve);
      }
      KeyPair keyPair;
      try {
        keyPair = KeyPair.newKeyPair();
      } catch (GeneralSecurityException e) {
        throw new CoseException("Error while generating key pair: ", e);
      }
      return withDParameter(keyPair.getPrivateKey())
          .withXCoordinate(keyPair.getPublicKey());
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  public byte[] sign(Algorithm algorithm, byte[] message) throws CborException, CoseException {
    if (privateKeyBytes == null) {
      throw new CoseException("Missing key material for signing.");
    }
    if (algorithm != Algorithm.SIGNING_ALGORITHM_EDDSA) {
      throw new CoseException("Incompatible key type.");
    }
    verifyAlgorithmMatchesKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_SIGN);
    return tinkSign(message);
  }

  private byte[] tinkSign(byte[] message) throws CoseException {
    try {
      Ed25519Sign signer = new Ed25519Sign(privateKeyBytes);
      return signer.sign(message);
    } catch (GeneralSecurityException e) {
      throw new CoseException("Error while signing message.", e);
    }
  }

  public void verify(Algorithm algorithm, byte[] message, byte[] signature)
      throws CborException, CoseException {
    if (algorithm != Algorithm.SIGNING_ALGORITHM_EDDSA) {
      throw new CoseException("Incompatible key type.");
    }
    verifyAlgorithmMatchesKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_VERIFY);
    tinkVerify(signature, message);
  }

  private void tinkVerify(byte[] signature, byte[] message) throws CoseException {
    try {
      Ed25519Verify verifier = new Ed25519Verify(publicKeyBytes);
      verifier.verify(signature, message);
    } catch (GeneralSecurityException e) {
      throw new CoseException("Error while verifying message.", e);
    }
  }
}
