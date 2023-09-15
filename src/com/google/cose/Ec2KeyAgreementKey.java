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

/** Implements EC2 COSE_Key spec for key wrapping purposes. */
public final class Ec2KeyAgreementKey extends Ec2Key {

  public Ec2KeyAgreementKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);

    if ((operations != null) && !operations.contains(Headers.KEY_OPERATIONS_WRAP_KEY)) {
      throw new CoseException("Wrapping key operation is needed for key agreement.");
    }
  }

  public static Ec2KeyAgreementKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static Ec2KeyAgreementKey decode(DataItem cborKey) throws CborException, CoseException {
    return new Ec2KeyAgreementKey(cborKey);
  }

  /** Generates a COSE formatted Ec2 key agreement key given a specific algorithm and curve. */
  public static Ec2KeyAgreementKey generateKey(Algorithm algorithm, int curve)
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

  public static class Builder extends Ec2Key.Builder<Builder> {
    @Override
    public Builder self() {
      return this;
    }

    @Override
    public Ec2KeyAgreementKey build() throws CborException, CoseException {
      return new Ec2KeyAgreementKey(compile());
    }

    @Override
    public Builder withOperations(Integer...operations) throws CoseException {
      for (int operation : operations) {
        if (operation != Headers.KEY_OPERATIONS_WRAP_KEY) {
          throw new CoseException("Only wrap key operation is permitted.");
        }
      }
      return super.withOperations(operations);
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
