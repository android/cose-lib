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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;

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

  /**
   * Generates a COSE formatted Ec2 signing key given a specific algorithm. The selected key size is
   * chosen based on section 6.2.1 of RFC 5656
   */
  public static Ec2SigningKey generateKey(Algorithm algorithm) throws CborException, CoseException {
    int curve;

    switch (algorithm) {
      case SIGNING_ALGORITHM_ECDSA_SHA_256:
        curve = Headers.CURVE_EC2_P256;
        break;

      case SIGNING_ALGORITHM_ECDSA_SHA_384:
        curve = Headers.CURVE_EC2_P384;
        break;

      case SIGNING_ALGORITHM_ECDSA_SHA_512:
        curve = Headers.CURVE_EC2_P521;
        break;

      default:
        throw new CoseException("Unsupported algorithm curve: " + algorithm.getJavaAlgorithmId());
    }

    return Ec2SigningKey.builder()
        .withGeneratedKeyPair(curve)
        .withAlgorithm(algorithm)
        .build();
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
