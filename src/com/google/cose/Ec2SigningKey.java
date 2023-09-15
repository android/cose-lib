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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

/** Implements EC2 COSE_Key spec for signing purposes. */
public final class Ec2SigningKey extends Ec2Key {
  public Ec2SigningKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);

    if ((operations != null)
        && !operations.contains(Headers.KEY_OPERATIONS_VERIFY)
        && !operations.contains(Headers.KEY_OPERATIONS_SIGN)) {
      throw new CoseException("Signing key requires either sign or verify operation.");
    }
  }

  public static Ec2SigningKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static Ec2SigningKey decode(DataItem cborKey) throws CborException, CoseException {
    return new Ec2SigningKey(cborKey);
  }

  // Big endian: Do not reuse for little endian encodings
  private static byte[] arrayFromBigNum(BigInteger num, int keySize)
      throws IllegalArgumentException {
    // Roundup arithmetic from bits to bytes.
    byte[] keyBytes = new byte[(keySize + 7) / 8];
    byte[] keyBytes2 = num.toByteArray();
    if (keyBytes.length == keyBytes2.length) {
      return keyBytes2;
    }
    if (keyBytes2.length > keyBytes.length) {
      // There should be no more than one padding(0) byte, invalid key otherwise.
      if (keyBytes2.length - keyBytes.length > 1 && keyBytes2[0] != 0) {
        throw new IllegalArgumentException();
      }
      System.arraycopy(keyBytes2, keyBytes2.length - keyBytes.length, keyBytes, 0, keyBytes.length);
    } else {
      System.arraycopy(
          keyBytes2, 0, keyBytes, keyBytes.length - keyBytes2.length, keyBytes2.length);
    }
    return keyBytes;
  }

  /**
   * Generates a COSE formatted Ec2 signing key given a specific algorithm. The selected key size is
   * chosen based on section 6.2.1 of RFC 5656
   */
  public static Ec2SigningKey generateKey(Algorithm algorithm) throws CborException, CoseException {
    KeyPair keyPair;
    int keySize;
    int header;
    String curveName;

    switch (algorithm) {
      case SIGNING_ALGORITHM_ECDSA_SHA_256:
        curveName = "secp256r1";
        keySize = 256;
        header = Headers.CURVE_EC2_P256;
        break;

      case SIGNING_ALGORITHM_ECDSA_SHA_384:
        curveName = "secp384r1";
        keySize = 384;
        header = Headers.CURVE_EC2_P384;
        break;

      case SIGNING_ALGORITHM_ECDSA_SHA_512:
        curveName = "secp521r1";
        keySize = 521;
        header = Headers.CURVE_EC2_P521;
        break;

      default:
        throw new CoseException("Unsupported algorithm curve: " + algorithm.getJavaAlgorithmId());
    }
    try {
      ECGenParameterSpec paramSpec = new ECGenParameterSpec(curveName);
      KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
      gen.initialize(paramSpec);
      keyPair = gen.genKeyPair();

      ECPoint pubPoint = ((ECPublicKey) keyPair.getPublic()).getW();
      byte[] x = arrayFromBigNum(pubPoint.getAffineX(), keySize);
      byte[] y = arrayFromBigNum(pubPoint.getAffineY(), keySize);

      byte[] privEncodedKey = keyPair.getPrivate().getEncoded();

      return Ec2SigningKey.builder()
          .withPrivateKeyRepresentation()
          .withPkcs8EncodedBytes(privEncodedKey)
          .withXCoordinate(x)
          .withYCoordinate(y)
          .withCurve(header)
          .withAlgorithm(algorithm)
          .build();
    } catch (NoSuchAlgorithmException e) {
      throw new CoseException("No provider for algorithm: " + algorithm.getJavaAlgorithmId(), e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new CoseException("The curve is not supported: " + algorithm.getJavaAlgorithmId(), e);
    } catch (IllegalArgumentException e) {
      throw new CoseException(
          "Invalid Coordinates generated for: " + algorithm.getJavaAlgorithmId(), e);
    }
  }

  /** Implements builder for Ec2SigningKey. */
  public static class Builder extends Ec2Key.Builder<Builder> {
    @Override
    public Builder self() {
      return this;
    }

    @Override
    public Ec2SigningKey build() throws CborException, CoseException {
      return new Ec2SigningKey(compile());
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
  }

  public static Builder builder() {
    return new Builder();
  }

  public byte[] sign(Algorithm algorithm, byte[] message, String provider)
      throws CborException, CoseException {
    if (keyPair.getPrivate() == null) {
      throw new CoseException("Missing key material for signing.");
    }
    verifyAlgorithmMatchesKey(algorithm);
    verifyAlgorithmAllowedByKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_SIGN);

    try {
      Signature signature;
      if (provider == null) {
        signature = Signature.getInstance(algorithm.getJavaAlgorithmId());
      } else {
        signature = Signature.getInstance(algorithm.getJavaAlgorithmId(), provider);
      }
      signature.initSign(keyPair.getPrivate());
      signature.update(message);
      return signature.sign();
    } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException
        | NoSuchProviderException e) {
      throw new CoseException("Error while signing message.", e);
    }
  }

  public void verify(Algorithm algorithm, byte[] message, byte[] signature, String provider)
      throws CborException, CoseException {
    verifyAlgorithmMatchesKey(algorithm);
    verifyAlgorithmAllowedByKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_VERIFY);

    try {
      Signature signer;
      if (provider == null) {
        signer = Signature.getInstance(algorithm.getJavaAlgorithmId());
      } else {
        signer = Signature.getInstance(algorithm.getJavaAlgorithmId(), provider);
      }
      signer.initVerify(keyPair.getPublic());
      signer.update(message);
      if (!signer.verify(signature)) {
        throw new CoseException("Failed verification.");
      }
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException
        | SignatureException e) {
      throw new CoseException("Error while verifying ", e);
    }
  }
}
