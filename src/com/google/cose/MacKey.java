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
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Implements COSE_Key spec for MAC purposes. */
public final class MacKey extends CoseKey {
  private final byte[] secretKey;

  private MacKey(final DataItem cborKey) throws CborException, CoseException {
    super(cborKey);
    if (labels.containsKey(Headers.KEY_PARAMETER_K)
        && labels.get(Headers.KEY_PARAMETER_K).getMajorType() == MajorType.BYTE_STRING) {
      byte[] keyMaterial = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_K)).getBytes();
      if (keyMaterial.length == 0) {
        throw new CoseException("Missing key material information.");
      } else {
        secretKey = keyMaterial;
      }
    } else {
      throw new CoseException("Missing key material information.");
    }

    if ((operations != null)
        && !operations.contains(Headers.KEY_OPERATIONS_MAC_CREATE)
        && !operations.contains(Headers.KEY_OPERATIONS_MAC_VERIFY)) {
      throw new CoseException("Mac key requires either create mac or verify mac operation.");
    }
  }

  public static MacKey parse(byte[] keyBytes) throws CborException, CoseException {
    return decode(CborUtils.decode(keyBytes));
  }

  public static MacKey decode(DataItem cborKey) throws CborException, CoseException {
    return new MacKey(cborKey);
  }

  public static class Builder extends CoseKey.Builder<Builder> {
    private byte[] secretKey;

    @Override
    Builder self() {
      return this;
    }

    @Override
    void verifyKeyMaterialPresentAndComplete() throws CoseException {
      if (secretKey == null) {
        throw new CoseException("Missing key material information.");
      }
    }

    @Override
    public MacKey build() throws CborException, CoseException {
      withKeyType(Headers.KEY_TYPE_SYMMETRIC);
      Map cborKey = compile();

      cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_K), new ByteString(secretKey));
      return new MacKey(cborKey);
    }

    @Override
    public Builder withOperations(Integer...operations) throws CoseException {
      for (int operation : operations) {
        if (operation != Headers.KEY_OPERATIONS_MAC_CREATE && operation != Headers.KEY_OPERATIONS_MAC_VERIFY)
          throw new CoseException("Mac key only supports CreateMac or VerifyMac operations.");
      }
      return super.withOperations(operations);
    }

    public Builder withSecretKey(byte[] k) {
      this.secretKey = k;
      return this;
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  public byte[] createMac(byte[] message, Algorithm algorithm) throws CborException, CoseException {
    verifyAlgorithmMatchesKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_MAC_CREATE);
    try {
      Mac mac = Mac.getInstance(algorithm.getJavaAlgorithmId());
      mac.init(new SecretKeySpec(secretKey, ""));
      mac.update(message);
      return mac.doFinal();
    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new CoseException("Error while creating mac", ex);
    }
  }

  public boolean verifyMac(byte[] message, Algorithm algorithm, final byte[] tag)
      throws CborException, CoseException {
    verifyAlgorithmMatchesKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_MAC_VERIFY);
    return Arrays.equals(createMac(message, algorithm), tag);
  }
}
