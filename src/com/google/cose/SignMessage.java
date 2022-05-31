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
import com.google.common.collect.ImmutableList;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Implements COSE_Sign class.
 */
public class SignMessage extends CoseMessage {
  private final byte[] message;
  private final ImmutableList<Signature> signatures;

  private SignMessage(Map protectedHeaders, Map unprotectedHeaders, byte[] message,
      ImmutableList<Signature> signatures) {
    super(protectedHeaders, unprotectedHeaders);
    this.message = message;
    this.signatures = signatures;
  }

  public static class Builder {
    private Map protectedHeaders;
    private Map unprotectedHeaders;
    private byte[] message;
    private ImmutableList<Signature> signatures;

    public SignMessage build() throws CoseException {
      if ((protectedHeaders != null) && (unprotectedHeaders != null)
          && (signatures != null && signatures.size() != 0)) {
        return new SignMessage(protectedHeaders, unprotectedHeaders, message, signatures);
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

    public Builder withSignatures(Signature...signatures) {
      return this.withSignatures(Arrays.asList(signatures));
    }

    public Builder withSignatures(List<Signature> signatures) {
      this.signatures = ImmutableList.copyOf(signatures);
      return this;
    }
  }

  @Override
  public DataItem encode() throws CoseException, CborException {
    if (signatures == null || signatures.size() == 0) {
      throw new CoseException("Error while serializing SignMessage. Signatures not found.");
    }

    ArrayBuilder<CborBuilder> messageBuilder = new CborBuilder().addArray();
    messageBuilder
        .add(CoseUtils.serializeProtectedHeaders(getProtectedHeaders()))
        .add(getUnprotectedHeaders())
        .add(message);

    ArrayBuilder<ArrayBuilder<CborBuilder>> signArrayBuilder = messageBuilder.addArray();

    for (Signature signature : signatures) {
      signArrayBuilder.add(signature.encode());
    }
    signArrayBuilder.end();

    return messageBuilder.end().build().get(0);
  }

  public static SignMessage deserialize(byte[] messageBytes) throws CoseException, CborException {
    return decode(CborUtils.decode(messageBytes));
  }

  public static SignMessage decode(DataItem cborMessage) throws CoseException, CborException {
    List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
    if (messageArray.size() != 4) {
      throw new CoseException("Error while decoding SignMessage. Expected 4 items,"
          + "received " + messageArray.size());
    }

    List<Signature> signatures = new ArrayList<>();
    for (DataItem signature : CborUtils.asArray(messageArray.get(3)).getDataItems()) {
      Signature decodedSignature = Signature.decode(signature);
      signatures.add(decodedSignature);
    }

    return SignMessage.builder()
        .withProtectedHeaders(CoseUtils.asProtectedHeadersMap(messageArray.get(0)))
        .withMessage(CoseUtils.getBytesFromBstrOrNilValue(messageArray.get(2)))
        .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
        .withSignatures(signatures)
        .build();
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
