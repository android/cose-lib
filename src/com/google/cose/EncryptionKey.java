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
import co.nstant.in.cbor.model.MajorType;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;

/** Implements COSE_Key spec for encryption purposes. */
public final class EncryptionKey extends Key {
  private final byte[] secretKey;
  // TODO: Add support for asymmetric encryption

  public EncryptionKey(byte[] secretKey) {
    this.secretKey = secretKey;
    this.cborKey = null;
  }

  public EncryptionKey(final DataItem cborKey, final byte[] secretKey) throws CborException {
    super(cborKey);
    this.secretKey = secretKey;
  }

  public EncryptionKey(final DataItem cborKey) throws CborException, CoseException {
    super(cborKey);
    if (labels.containsKey(Headers.KEY_PARAMETER_K)
        && labels.get(Headers.KEY_PARAMETER_K).getMajorType() == MajorType.BYTE_STRING) {
      secretKey = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_K)).getBytes();
    } else {
      throw new IllegalStateException("Need key material information.");
    }

    if ((operations == null)
        || (operations.contains(Headers.KEY_OPERATIONS_DECRYPT)
        && operations.contains(Headers.KEY_OPERATIONS_ENCRYPT))) {
      return;
    }
    throw new CoseException("Encryption key requires encrypt and decrypt operations.");
  }

  public static EncryptionKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static EncryptionKey decode(DataItem cborKey) throws CborException, CoseException {
    return new EncryptionKey(cborKey);
  }
}
