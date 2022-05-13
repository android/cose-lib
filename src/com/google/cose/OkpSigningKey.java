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
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;

/** Implements COSE_Key spec for signing purposes. */
public final class OkpSigningKey extends Key {
  byte[] privateKeyBytes;
  byte[] publicKeyBytes;

  OkpSigningKey(byte[] privateKeyBytes, byte[] publicKeyBytes) {
    this.privateKeyBytes = privateKeyBytes;
    this.publicKeyBytes = publicKeyBytes;
    this.cborKey = null;
  }

  OkpSigningKey(DataItem cborKey) throws CoseException, CborException {
    super(cborKey);

    if (keyType != Headers.KEY_TYPE_OKP) {
      throw new CoseException(String.format("Expecting OKP key (type 1), found type %d.", keyType));
    }
    int curve = CborUtils.asInteger(labels.get(Headers.KEY_PARAMETER_CURVE));
    if (curve != Headers.CURVE_OKP_Ed25519) {
      throw new UnsupportedOperationException("Unsupported curve.");
    }

    privateKeyBytes = getPrivateKeyBytes();
    publicKeyBytes = getPublicKeyBytes();
    if ((operations == null)
        || (operations.contains(Headers.KEY_OPERATIONS_VERIFY)
        && operations.contains(Headers.KEY_OPERATIONS_SIGN))) {
      return;
    }

    throw new CoseException("Signing key requires sign and verify operations.");
  }

  private byte[] getPrivateKeyBytes() throws CborException {
    if (labels.containsKey(Headers.KEY_PARAMETER_D)) {
      return CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_D)).getBytes();
    }
    return null;
  }

  private byte[] getPublicKeyBytes() throws CborException {
    if (labels.containsKey(Headers.KEY_PARAMETER_X)) {
      return CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_X)).getBytes();
    }
    return null;
  }

  public static OkpSigningKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static OkpSigningKey decode(DataItem cborKey) throws CborException, CoseException {
    return new OkpSigningKey(cborKey);
  }
}
