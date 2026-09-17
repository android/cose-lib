/*
 * Copyright 2026 Google LLC
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
import co.nstant.in.cbor.model.Map;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

/** Implements AKP COSE_Key spec for signing purposes. */
public final class AkpSigningKey extends AkpKey {

  public AkpSigningKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);

    if (operations != null
        && !operations.contains(Headers.KEY_OPERATIONS_VERIFY)
        && !operations.contains(Headers.KEY_OPERATIONS_SIGN)) {
      throw new CoseException("Signing key requires either sign or verify operation.");
    }
  }

  public static AkpSigningKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static AkpSigningKey decode(DataItem cborKey) throws CborException, CoseException {
    return new AkpSigningKey(cborKey);
  }

  /**
   * Generates a COSE formatted AKP signing key given a specific algorithm. The selected key size is
   * chosen based on table 2 of FIPS-204, document link: https://doi.org/10.6028/NIST.FIPS.204.
   *
   * <p>JCE supports MLDSA but it uses the extended private key representation. For now, we will
   * only support Conscrypt provider so that we can use the 32-byte seed representation for the
   * private key as described in the draft RFC for AKP keys.
   */
  public static AkpSigningKey generateKey(Algorithm algorithm, String provider)
      throws CborException, CoseException {
    KeyPair keyPair;

    // Support for Conscrypt only till we port to openjdk 24+
    if (!isConscryptProvider(provider)) {
      throw new IllegalArgumentException("Only Conscrypt provider is supported.");
    }

    if (!isAkpAlgorithm(algorithm)) {
      throw new CoseException("Unsupported algorithm: " + algorithm.getJavaAlgorithmId());
    }

    try {
      KeyPairGenerator keyPairGenerator;
      KeyFactory keyFactory;
      switch (algorithm) {
        case SIGNING_ALGORITHM_MLDSA_44 -> {
          keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA-44", provider);
          keyFactory = KeyFactory.getInstance("ML-DSA-44", provider);
        }
        case SIGNING_ALGORITHM_MLDSA_65 -> {
          keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA-65", provider);
          keyFactory = KeyFactory.getInstance("ML-DSA-65", provider);
        }
        case SIGNING_ALGORITHM_MLDSA_87 -> {
          keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA-87", provider);
          keyFactory = KeyFactory.getInstance("ML-DSA-87", provider);
        }
        default ->
            throw new CoseException("Unsupported algorithm: " + algorithm.getJavaAlgorithmId());
      }
      keyPair = keyPairGenerator.generateKeyPair();

      byte[] seed = keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class).getEncoded();
      byte[] pubBytes = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class).getEncoded();

      return AkpSigningKey.builder()
          .withPrivateKey(seed)
          .withPublicKey(pubBytes)
          .withAlgorithm(algorithm)
          .build();
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new CoseException("No provider for algorithm: " + algorithm.getJavaAlgorithmId(), e);
    } catch (InvalidKeySpecException e) {
      throw new CoseException("Error while extracting key material.", e);
    } catch (IllegalArgumentException e) {
      throw new CoseException(
          "Error while generating key for: " + algorithm.getJavaAlgorithmId(), e);
    }
  }

  /** Implements builder for AkpSigningKey. */
  public static class Builder extends AkpKey.Builder<Builder> {

    @Override
    public Builder self() {
      return this;
    }

    @Override
    public AkpSigningKey build() throws CborException, CoseException {
      Map cborKey = compile();
      return new AkpSigningKey(cborKey);
    }

    @Override
    public Builder withOperations(Integer... operations) throws CoseException {
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
    if (privateKeyBytes == null || privateKeyBytes.length == 0) {
      throw new CoseException("Missing key material for signing.");
    }
    verifyAlgorithmMatchesKey(algorithm);
    verifyAlgorithmAllowedByKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_SIGN);
    if (!isConscryptProvider(provider)) {
      throw new IllegalArgumentException("Only Conscrypt provider is supported.");
    }

    try {
      RawKeySpec privateKeySpec = new RawKeySpec(privateKeyBytes);
      KeyFactory keyFactory;
      Signature signature;

      switch (algorithm) {
        case SIGNING_ALGORITHM_MLDSA_44 -> {
          keyFactory = KeyFactory.getInstance("ML-DSA-44", provider);
          signature = Signature.getInstance("ML-DSA-44", provider);
        }
        case SIGNING_ALGORITHM_MLDSA_65 -> {
          keyFactory = KeyFactory.getInstance("ML-DSA-65", provider);
          signature = Signature.getInstance("ML-DSA-65", provider);
        }
        case SIGNING_ALGORITHM_MLDSA_87 -> {
          keyFactory = KeyFactory.getInstance("ML-DSA-87", provider);
          signature = Signature.getInstance("ML-DSA-87", provider);
        }
        default -> throw new CoseException("Unknown algorithm.");
      }
      PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

      signature.initSign(privateKey);
      signature.update(message);
      return signature.sign();
    } catch (NoSuchAlgorithmException
        | SignatureException
        | InvalidKeySpecException
        | InvalidKeyException
        | NoSuchProviderException e) {
      throw new CoseException("Error while signing message.", e);
    }
  }

  public void verify(Algorithm algorithm, byte[] message, byte[] signature, String provider)
      throws CborException, CoseException {
    verifyAlgorithmMatchesKey(algorithm);
    verifyAlgorithmAllowedByKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_VERIFY);
    if (!isConscryptProvider(provider)) {
      throw new IllegalArgumentException("Only Conscrypt provider is supported.");
    }

    try {
      RawKeySpec publicKeySpec = new RawKeySpec(publicKeyBytes);
      KeyFactory keyFactory;
      Signature signer;

      switch (algorithm) {
        case SIGNING_ALGORITHM_MLDSA_44 -> {
          keyFactory = KeyFactory.getInstance("ML-DSA-44", provider);
          signer = Signature.getInstance("ML-DSA-44", provider);
        }
        case SIGNING_ALGORITHM_MLDSA_65 -> {
          keyFactory = KeyFactory.getInstance("ML-DSA-65", provider);
          signer = Signature.getInstance("ML-DSA-65", provider);
        }
        case SIGNING_ALGORITHM_MLDSA_87 -> {
          keyFactory = KeyFactory.getInstance("ML-DSA-87", provider);
          signer = Signature.getInstance("ML-DSA-87", provider);
        }
        default -> throw new CoseException("Unknown algorithm.");
      }
      PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
      signer.initVerify(publicKey);
      signer.update(message);
      if (!signer.verify(signature)) {
        throw new CoseException("Failed verification.");
      }
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | InvalidKeyException
        | InvalidKeySpecException
        | SignatureException e) {
      throw new CoseException("Error while verifying ", e);
    }
  }

  /** Representation of the raw keys for interoperability with Conscrypt. */
  public static final class RawKeySpec extends EncodedKeySpec {
    public RawKeySpec(byte[] encoded) {
      super(encoded);
    }

    @Override
    public String getFormat() {
      return "raw";
    }
  }
}
