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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import org.bouncycastle.math.ec.rfc7748.X25519;

/**
 * Implements OKP COSE_Key spec for key wrapping purposes.
 * Currently, only supports X25519 curve.
 */
public final class OkpKeyAgreementKey extends OkpKey {
  private static final int SIGN_POSITIVE = 1;

  public OkpKeyAgreementKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);

    int curve = CborUtils.asInteger(labels.get(Headers.KEY_PARAMETER_CURVE));
    if (curve != Headers.CURVE_OKP_X25519) {
      throw new CoseException(CoseException.UNSUPPORTED_CURVE_EXCEPTION_MESSAGE);
    }

    if ((operations != null) && !operations.contains(Headers.KEY_OPERATIONS_WRAP_KEY)) {
      throw new CoseException("Only wrap key operation supported with this key.");
    }
  }

  public static OkpKeyAgreementKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static OkpKeyAgreementKey decode(DataItem cborKey) throws CborException, CoseException {
    return new OkpKeyAgreementKey(cborKey);
  }

  @Override
  protected byte[] publicFromPrivate(byte[] privateKey) throws CoseException {
    byte[] r = new byte[32];
    X25519.generatePublicKey(privateKeyBytes, 0, r, 0);
    return r;
  }

  @Override
  public PublicKey getPublicKey() throws CoseException {
    try {
      BigInteger u = new BigInteger(SIGN_POSITIVE, publicKeyBytes);
      XECPublicKeySpec spec = new XECPublicKeySpec(NamedParameterSpec.X25519, u);
      return KeyFactory.getInstance("X25519").generatePublic(spec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new CoseException("Failed to generate X25519 public key", e);
    }
  }

  /** Generates a COSE formatted OKP key agreement key from scratch. */
  public static OkpKeyAgreementKey generateKey(Algorithm algorithm, int curve)
      throws CborException, CoseException {
    switch (algorithm) {
      case ECDH_ES_HKDF_256:
      return builder()
          .withGeneratedKeyPair(curve)
          .withAlgorithm(algorithm)
          .build();

      default:
        throw new CoseException("Unsupported algorithm: " + algorithm.getJavaAlgorithmId());
    }
  }

  public static class Builder extends OkpKey.Builder<Builder> {
    @Override
    public Builder self() {
      return this;
    }

    @Override
    public OkpKeyAgreementKey build() throws CborException, CoseException {
      withCurve(Headers.CURVE_OKP_X25519);
      return new OkpKeyAgreementKey(compile());
    }

    @Override
    public Builder withOperations(Integer...operations) throws CoseException {
      for (int operation : operations) {
        if (operation != Headers.KEY_OPERATIONS_WRAP_KEY
            && operation != Headers.KEY_OPERATIONS_UNWRAP_KEY) {
          throw new CoseException("Key Agreement only supports Wrap Key or Unwrap Key operations.");
        }
      }
      return super.withOperations(operations);
    }

    public Builder withGeneratedKeyPair(int curve) throws CoseException {
      if (curve != Headers.CURVE_OKP_X25519) {
        throw new CoseException("Unsupported curve: " + curve);
      }
      try {
        KeyPair keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        return withDParameter(((XECPrivateKey) keyPair.getPrivate()).getScalar().get())
            .withXCoordinate(((XECPublicKey) keyPair.getPublic()).getU().toByteArray());
      } catch (GeneralSecurityException e) {
        throw new CoseException("Failed to generate key pair", e);
      }
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
