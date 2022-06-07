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
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import com.google.cose.utils.Headers;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.LinkedHashSet;
import java.util.Set;

/** Implements EC2 COSE_Key spec for signing purposes. */
public final class Ec2SigningKey extends CoseKey {
  private static final int SIGN_POSITIVE = 1;

  KeyPair keyPair;

  public Ec2SigningKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);

    keyPair = getKeyPairFromCbor();

    if ((operations != null)
        && !operations.contains(Headers.KEY_OPERATIONS_VERIFY)
        && !operations.contains(Headers.KEY_OPERATIONS_SIGN)) {
      throw new CoseException("Signing key requires either sign or verify operation.");
    }
  }

  public static class Builder {
    private String keyId;
    private Algorithm algorithm;
    private final Set<Integer> operations = new LinkedHashSet<>();
    private byte[] baseIv;
    private Integer curve = null;
    private byte[] xCor;
    private byte[] yCor;
    private byte[] dParameter;

    public Ec2SigningKey build() throws CborException, CoseException {
      if (curve == null) {
        throw new CoseException("Need curve information.");
      }
      if (dParameter == null && (xCor == null || yCor == null)) {
        throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
      }
      if (xCor == null ^ yCor == null) {
        // If we have only one public key coordinate, raise an exception
        throw new CoseException("Need both x and y coordinate information for EC2 public key.");
      }

      Map cborKey = new Map();
      cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_TYPE),
          new UnsignedInteger(Headers.KEY_TYPE_EC2));

      if (keyId != null) {
        cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_ID),
            new ByteString(keyId.getBytes()));
      }
      if (algorithm != null) {
        cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_ALGORITHM),
            algorithm.getCoseAlgorithmId());
      }
      if (operations.size() != 0) {
        Array keyOperations = new Array();
        for (int operation: operations) {
          keyOperations.add(new UnsignedInteger(operation));
        }
        cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_OPERATIONS), keyOperations);
      }
      if (baseIv != null) {
        cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_BASE_IV),
            new ByteString(baseIv));
      }

      cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_CURVE), new UnsignedInteger(curve));
      if (xCor != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_X), new ByteString(xCor));
      }
      if (yCor != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_Y), new ByteString(yCor));
      }
      if (dParameter != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_D), new ByteString(dParameter));
      }
      return new Ec2SigningKey(cborKey);
    }

    public Builder withKeyId(String keyId) {
      this.keyId = keyId;
      return this;
    }

    public Builder withAlgorithm(Algorithm algorithm) {
      this.algorithm = algorithm;
      return this;
    }

    public Builder withOperations(Integer...operations) throws CoseException {
      for (int operation : operations) {
        if (operation != Headers.KEY_OPERATIONS_SIGN && operation != Headers.KEY_OPERATIONS_VERIFY)
          throw new CoseException("Signing key only supports Sign or Verify operations.");
        this.operations.add(operation);
      }
      return this;
    }

    public Builder withBaseIv(byte[] baseIv) {
      this.baseIv = baseIv;
      return this;
    }

    public Builder withCurve(int curve) throws CoseException {
      if ((curve < 0) || (curve > Headers.CURVE_EC2_P521)) {
        throw new CoseException(CoseException.UNSUPPORTED_CURVE_EXCEPTION_MESSAGE);
      }
      this.curve = curve;
      return this;
    }

    public Builder withXCoordinate(byte[] xCor) {
      this.xCor = xCor;
      return this;
    }

    public Builder withYCoordinate(byte[] yCor) {
      this.yCor = yCor;
      return this;
    }

    public PrivateKeyRepresentationBuilder withPrivateKeyRepresentation() {
      return new PrivateKeyRepresentationBuilder(this);
    }

    /**
     * Helper class to get the raw bytes out of the encoded private keys.
     */
    public static class PrivateKeyRepresentationBuilder {
      Builder builder;

      // To prevent object instantiation from outside the class.
      private PrivateKeyRepresentationBuilder() {}

      PrivateKeyRepresentationBuilder(Builder builder) {
        this.builder = builder;
      }

      public Builder withPrivateKey(ECPrivateKey privateKey) {
        builder.dParameter = privateKey.getS().toByteArray();
        return builder;
      }

      public Builder withPkcs8EncodedBytes(byte[] keyBytes) throws CoseException {
        ECPrivateKey key = CoseUtils.getEc2PrivateKeyFromEncodedKeyBytes(keyBytes);
        builder.dParameter = key.getS().toByteArray();
        return builder;
      }

      /**
       * This function expects the BigInteger byte array of the private key. This is typically the
       * multiplier in the EC2 private key which can generate EC2 public key from generator point.
       * @param rawBytes byte array representation of BigInteger
       * @return {@link Ec2SigningKey.Builder}
       */
      public Builder withDParameter(byte[] rawBytes) {
        builder.dParameter = rawBytes;
        return builder;
      }
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  private KeyPair getKeyPairFromCbor() throws CborException, CoseException {
    if (keyType != Headers.KEY_TYPE_EC2) {
      throw new CoseException("Expecting EC2 key (type 2), found type " + keyType);
    }

    final KeyPair keyPair;
    // Get curve information
    int curve = CborUtils.asInteger(labels.get(Headers.KEY_PARAMETER_CURVE));

    // Get private key.
    final ECPrivateKey privateKey;
    if (labels.containsKey(Headers.KEY_PARAMETER_D)) {
      byte[] key = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_D)).getBytes();
      if (key.length == 0) {
        throw new CoseException("Cannot decode private key. Missing coordinate information.");
      }
      privateKey = CoseUtils.getEc2PrivateKeyFromInteger(curve, new BigInteger(SIGN_POSITIVE, key));
    } else {
      privateKey = null;
    }

    if (!labels.containsKey(Headers.KEY_PARAMETER_X)) {
      if (privateKey == null) {
        throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
      } else {
        return new KeyPair(CoseUtils.getEc2PublicKeyFromPrivateKey(curve, privateKey), privateKey);
      }
    }

    final ByteString xCor = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_X));
    // Get the public key for EC2 key.
    // We should not have a case where x is provided but y is not.
    if (!labels.containsKey(Headers.KEY_PARAMETER_Y)) {
      throw new IllegalStateException("X coordinate provided but Y coordinate is missing.");
    }
    final ByteString yCor = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_Y));
    final PublicKey publicKey = CoseUtils.getEc2PublicKeyFromCoordinates(
        curve,
        new BigInteger(SIGN_POSITIVE, xCor.getBytes()),
        new BigInteger(SIGN_POSITIVE, yCor.getBytes())
    );
    keyPair = new KeyPair(publicKey, privateKey);
    return keyPair;
  }

  public static Ec2SigningKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static Ec2SigningKey decode(DataItem cborKey) throws CborException, CoseException {
    return new Ec2SigningKey(cborKey);
  }

  public byte[] sign(Algorithm algorithm, byte[] message, String provider) throws CoseException {
    if (keyPair.getPrivate() == null) {
      throw new CoseException("Missing key material for signing.");
    }
    if (algorithm != Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256) {
      // TODO: Add support for other algorithms.
      throw new CoseException("Unsupported algorithm.");
    }

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
      throws CoseException {
    if (algorithm != Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256) {
      // TODO: Add support for other algorithms.
      throw new CoseException("Unsupported algorithm.");
    }

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
