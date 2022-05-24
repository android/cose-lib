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
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import java.util.List;

/**
 * Implements COSE_Sign1 message structure.
 */
public class Sign1Message extends CoseMessage {
  private final byte[] message;
  private final byte[] signature;

  Sign1Message(Map protectedHeaders, Map unprotectedHeaders, byte[] message, byte[] sign) {
    super(protectedHeaders, unprotectedHeaders);
    this.message = message;
    this.signature = sign;
  }

  static class Builder {
    private Map protectedHeaders;
    private Map unprotectedHeaders;
    private byte[] message;
    private byte[] signature;
    public Sign1Message build() throws CoseException {
      if ((protectedHeaders != null) && (unprotectedHeaders != null) && (signature != null)) {
        return new Sign1Message(protectedHeaders, unprotectedHeaders, message, signature);
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

    public Builder withMessage(byte[] message) {
      this.message = message;
      return this;
    }

    public Builder withSignature(byte[] signature) {
      this.signature = signature;
      return this;
    }
  }

  @Override
  public DataItem encode() throws CborException {
    ArrayBuilder<CborBuilder> signArrayBuilder = new CborBuilder().addArray();
    signArrayBuilder
        .add(CoseUtils.serializeProtectedHeaders(getProtectedHeaders()))
        .add(getUnprotectedHeaders())
        .add(message)
        .add(signature);
    return signArrayBuilder.end().build().get(0);
  }

  public static Sign1Message deserialize(byte[] messageBytes) throws CoseException, CborException {
    return decode(CborUtils.decode(messageBytes));
  }

  public static Sign1Message decode(DataItem cborMessage) throws CoseException, CborException {
    List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
    if (messageArray.size() != 4) {
      throw new CoseException("Error while decoding Sign1Message. Expected 4 items,"
          + "received " + messageArray.size());
    }
    byte[] protectedHeaderBytes = CborUtils.asByteString(messageArray.get(0)).getBytes();
    return Sign1Message.builder()
        .withProtectedHeaders(CoseUtils.getProtectedHeadersFromBytes(protectedHeaderBytes))
        .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
        .withMessage(CoseUtils.getBytesFromBstrOrNilValue(messageArray.get(2)))
        .withSignature(CborUtils.asByteString(messageArray.get(3)).getBytes())
        .build();
  }

  public byte[] getMessage() {
    return message;
  }

  public byte[] getSignature() {
    return signature;
  }

  public static Builder builder() {
    return new Builder();
  }
}
