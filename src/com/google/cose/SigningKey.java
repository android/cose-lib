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
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import com.google.cose.utils.Headers;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/** Implements COSE_Key spec for signing purposes. */
public final class SigningKey extends Key {
  KeyPair keyPair;

  SigningKey(KeyPair keyPair) {
    this.keyPair = keyPair;
    this.cborKey = null;
  }

  SigningKey(DataItem cborKey, KeyPair keyPair) throws CborException {
    super(cborKey);
    this.keyPair = keyPair;
  }

  SigningKey(DataItem cborKey) throws CoseException, CborException {
    super(cborKey);
    if ((operations == null)
        || (operations.contains(Headers.KEY_OPERATIONS_VERIFY)
        && operations.contains(Headers.KEY_OPERATIONS_SIGN))) {
      return;
    }

    keyPair = generateKeyPair();
  }

  private KeyPair generateKeyPair() throws CoseException, CborException {
    if ((keyType != Headers.KEY_TYPE_ECC) && (keyType != Headers.KEY_TYPE_OKP)) {
      throw new CoseException(String.format("Illegal key type found for signing. Expected 2 (ECC)"
              + " or 1 (OKP), found %d.", keyType));
    }

    final KeyPair keyPair;
    // Get curve information
    int curve = CborUtils.asInteger(labels.get(Headers.KEY_PARAMETER_CURVE));

    // Generate private key.
    final PrivateKey privateKey;
    if (labels.containsKey(Headers.KEY_PARAMETER_D)) {
      final ByteString key = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_D));
      privateKey = CoseUtils.generateEccPrivateKey(curve, new BigInteger(1, key.getBytes()));
    } else {
      privateKey = null;
    }

    if (!labels.containsKey(Headers.KEY_PARAMETER_X)) {
      if (privateKey == null) {
        throw new IllegalStateException("Missing key material information.");
      } else {
        return new KeyPair(null, privateKey);
      }
    }

    final ByteString xCor = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_X));
    if (keyType == Headers.KEY_TYPE_ECC) {
      // Generate the public key for ECC key.
      // We should not have a case where x is provided but y is not.
      if (!labels.containsKey(Headers.KEY_PARAMETER_Y)) {
        if (privateKey == null) {
          throw new IllegalStateException("Missing Y coordinate information.");
        } else {
          throw new IllegalStateException("X coordinate provided but Y coordinate is missing.");
        }
      }
      final ByteString yCor = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_Y));
      final PublicKey publicKey = CoseUtils.generateEccPublicKey(curve,
          new BigInteger(1, xCor.getBytes()), new BigInteger(1, yCor.getBytes()));
      keyPair = new KeyPair(publicKey, privateKey);
    } else {
      // Generate the public key for OKP key.
      // TODO: Add support for generating OKP key.
      throw new UnsupportedOperationException();
    }
    return keyPair;
  }

  public static SigningKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static SigningKey decode(DataItem cborKey) throws CborException, CoseException {
    return new SigningKey(cborKey);
  }
}
