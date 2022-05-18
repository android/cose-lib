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
import com.google.cose.utils.Headers;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Implements OKP COSE_Key spec for signing purposes.
 * Currently only supports Ed25519 curve.
 */
public final class OkpSigningKey extends CoseKey {
  byte[] privateKeyBytes;
  byte[] publicKeyBytes;

  public OkpSigningKey(DataItem cborKey) throws CoseException, CborException {
    super(cborKey);

    if (keyType != Headers.KEY_TYPE_OKP) {
      throw new CoseException("Expecting OKP key (type 1), found type " + keyType);
    }
    int curve = CborUtils.asInteger(labels.get(Headers.KEY_PARAMETER_CURVE));
    if (curve != Headers.CURVE_OKP_Ed25519) {
      throw new CoseException(CoseException.UNSUPPORTED_CURVE_EXCEPTION_MESSAGE);
    }

    privateKeyBytes = getPrivateKeyBytes();
    publicKeyBytes = getPublicKeyBytes();

    if ((operations != null)
        && !operations.contains(Headers.KEY_OPERATIONS_VERIFY)
        && !operations.contains(Headers.KEY_OPERATIONS_SIGN)) {
      throw new CoseException("Signing key requires either sign or verify operation.");
    }
  }

  static class Builder {
    private String keyId;
    private Algorithm algorithm;
    private final Set<Integer> operations;
    private byte[] baseIv;
    private byte[] xCor;
    private byte[] dParameter;

    Builder() {
      operations = new HashSet<>();
    }

    public OkpSigningKey build() throws CoseException, CborException {
      if (dParameter == null && xCor == null) {
        throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
      }

      if (operations.size() != 0 && !operations.contains(Headers.KEY_OPERATIONS_VERIFY)
          && !operations.contains(Headers.KEY_OPERATIONS_SIGN)) {
        throw new CoseException("Need Sign and Verify operation for the signing key.");
      }

      Map cborKey = new Map();
      cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_TYPE),
          new UnsignedInteger(Headers.KEY_TYPE_OKP));

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
      cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_CURVE),
          new UnsignedInteger(Headers.CURVE_OKP_Ed25519));
      if (xCor != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_X), new ByteString(xCor));
      }
      if (dParameter != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_D), new ByteString(dParameter));
      }
      return new OkpSigningKey(cborKey);
    }

    public Builder withKeyId(String keyId) {
      this.keyId = keyId;
      return this;
    }

    public Builder withAlgorithm(Algorithm algorithm) {
      this.algorithm = algorithm;
      return this;
    }

    public Builder withOperations(Integer...operations) {
      this.operations.addAll(Arrays.asList(operations));
      return this;
    }

    public Builder withBaseIv(byte[] baseIv) {
      this.baseIv = baseIv;
      return this;
    }

    public Builder withXCoordinate(byte[] xCor) {
      this.xCor = xCor;
      return this;
    }

    public Builder withDParameter(byte[] dParam) {
      this.dParameter = dParam;
      return this;
    }
  }

  public static Builder builder() {
    return new Builder();
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
