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
import org.bouncycastle.math.ec.rfc7748.X25519;

/**
 * Implements OKP COSE_Key spec for key wrapping purposes.
 * Currently, only supports X25519 curve.
 */
public final class OkpKeyAgreementKey extends OkpKey {
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
  }

  public static Builder builder() {
    return new Builder();
  }
}
