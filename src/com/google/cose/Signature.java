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

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import java.util.List;

/**
 * Encodes the COSE_Signature structure.
 */
public class Signature extends CoseMessage {
  private final byte[] signature;

  Signature(Map protectedHeaders, Map unprotectedHeaders, byte[] signature) {
    super(protectedHeaders, unprotectedHeaders);
    this.signature = signature;
  }

  static class Builder {
    private Map protectedHeaders;
    private Map unprotectedHeaders;
    private byte[] signature;

    public Signature build() throws CoseException {
      if ((protectedHeaders != null) && (unprotectedHeaders != null) && (signature != null)) {
        return new Signature(protectedHeaders, unprotectedHeaders, signature);
      } else {
        throw new CoseException("Some fields are missing.");
      }
    }

    public Builder withProtectedHeaders(Map protectedHeaders) {
      this.protectedHeaders = protectedHeaders;
      return this;
    }

    public Builder withUnprotectedHeaders(Map unprotectedHeaders) {
      this.unprotectedHeaders = unprotectedHeaders;
      return this;
    }

    public Builder withSignature(byte[] signature) {
      this.signature = signature;
      return this;
    }
  }

  @Override
  public DataItem encode() throws CborException {
    return new CborBuilder().addArray()
        .add(CoseUtils.serializeProtectedHeaders(getProtectedHeaders()))
        .add(getUnprotectedHeaders()).add(signature).end().build().get(0);
  }

  public static Signature deserialize(byte[] signature) throws CoseException, CborException {
    return decode(CborUtils.decode(signature));
  }

  public static Signature decode(DataItem cborMessage) throws CoseException, CborException {
    List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
    if (messageArray.size() != 3) {
      throw new CoseException("Error while decoding Signature. Expected 3 items,"
          + "received " + messageArray.size());
    }

    byte[] protectedHeaderBytes = CborUtils.asByteString(messageArray.get(0)).getBytes();
    return Signature.builder()
        .withProtectedHeaders(CoseUtils.getProtectedHeadersFromBytes(protectedHeaderBytes))
        .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
        .withSignature(CborUtils.asByteString(messageArray.get(2)).getBytes())
        .build();
  }

  public byte[] getSignature() {
    return signature;
  }

  public static Builder builder() {
    return new Builder();
  }
}
