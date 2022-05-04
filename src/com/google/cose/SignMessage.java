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
import java.util.List;
import java.util.stream.Collectors;

/**
 * Implements COSE_Sign class.
 */
public class SignMessage extends CoseMessage {
  private final byte[] message;
  private final List<Signature> signatures;

  SignMessage(byte[] protectedHeaderBytes, Map unprotectedHeaders, byte[] message,
      List<Signature> signatures) {
    super(protectedHeaderBytes, unprotectedHeaders);
    this.message = message;
    this.signatures = signatures;
  }

  static class Builder {
    private byte[] protectedHeaderBytes;
    private Map unprotectedHeaders;
    private byte[] message;
    private List<Signature> signatures;

    public SignMessage build() {
      if ((protectedHeaderBytes != null) && (unprotectedHeaders != null) && (message != null)
          && (signatures != null)) {
        return new SignMessage(protectedHeaderBytes, unprotectedHeaders, message, signatures);
      } else {
        throw new CoseException("Some fields are missing.");
      }
    }

    public Builder withProtectedHeaderBytes(byte[] protectedHeaderBytes) {
      this.protectedHeaderBytes = protectedHeaderBytes;
      return this;
    }

    public Builder withProtectedHeaders(Map protectedHeaders) {
      if (protectedHeaderBytes != null) {
        throw new CoseException("Cannot use both withProtectedHeaderBytes and withProtectedHeaders");
      }
      if (protectedHeaders == null || protectedHeaders.getKeys().size() == 0) {
        this.protectedHeaderBytes = new byte[0];
      } else {
        this.protectedHeaderBytes = CborUtils.encode(protectedHeaders);
      }
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

    public Builder withSignatures(List<Signature> signatures) {
      this.signatures = signatures;
      return this;
    }
  }

  @Override
  public DataItem encode() {
    ArrayBuilder<CborBuilder> messageBuilder = new CborBuilder().addArray();
    messageBuilder.add(getProtectedHeaderBytes()).add(getUnprotectedHeaders()).add(message);
    ArrayBuilder<ArrayBuilder<CborBuilder>> signArrayBuilder = messageBuilder.addArray();

    if (signatures == null) {
      throw new CoseException("Error while serializing SignMessage. Signatures not found.");
    }

    for (Signature signature : signatures) {
      signArrayBuilder.add(signature.encode());
    }
    signArrayBuilder.end();

    return messageBuilder.end().build().get(0);
  }

  public static SignMessage deserialize(byte[] messageBytes) {
    return decode(CborUtils.decode(messageBytes));
  }

  public static SignMessage decode(DataItem cborMessage) {
    try {
      List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
      if (messageArray.size() != 4) {
        throw new CoseException("Error while decoding EncryptMessage. Expected 4 items,"
            + "received " + messageArray.size());
      }
      List<DataItem> signatures = CborUtils.asArray(messageArray.get(3)).getDataItems();

      return SignMessage.builder()
          .withProtectedHeaderBytes(CborUtils.asByteString(messageArray.get(0)).getBytes())
          .withMessage(CborUtils.asByteString(messageArray.get(2)).getBytes())
          .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
          .withSignatures(signatures.stream().map(Signature::decode).collect(Collectors.toList()))
          .build();
    } catch (CborException ex) {
      throw new CoseException("Error while decoding EncryptMessage.", ex);
    }
  }

  public byte[] getMessage() {
    return message;
  }

  public List<Signature> getSignatures() {
    return signatures;
  }

  public static Builder builder() {
    return new Builder();
  }
}
