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
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.SimpleValueType;
import co.nstant.in.cbor.model.Special;
import co.nstant.in.cbor.model.SpecialType;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import java.util.List;

/**
 * Implements COSE_Encrypt0 message.
 */
public class Encrypt0Message extends CoseMessage {
  byte[] ciphertext;

  private Encrypt0Message(Map protectedHeaders, Map unprotectedHeaders, byte[] ciphertext) {
    super(protectedHeaders, unprotectedHeaders);
    this.ciphertext = ciphertext;
  }

  static class Builder {
    private Map protectedHeaders;
    private Map unprotectedHeaders;
    private byte[] ciphertext;
    public Encrypt0Message build() throws CoseException {
      if ((protectedHeaders != null) && (unprotectedHeaders != null)) {
        return new Encrypt0Message(protectedHeaders, unprotectedHeaders, ciphertext);
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

    public Builder withCiphertext(byte[] ciphertext) {
      this.ciphertext = ciphertext;
      return this;
    }
  }

  @Override
  public DataItem encode() throws CborException {
    ArrayBuilder<CborBuilder> encryptArrayBuilder = new CborBuilder().addArray();
    encryptArrayBuilder
        .add(CoseUtils.serializeProtectedHeaders(getProtectedHeaders()))
        .add(getUnprotectedHeaders())
        .add(getCiphertext());
    return encryptArrayBuilder.end().build().get(0);
  }

  public static Encrypt0Message deserialize(byte[] messageBytes) throws CoseException, CborException {
    return decode(CborUtils.decode(messageBytes));
  }

  public static Encrypt0Message decode(DataItem cborMessage) throws CoseException, CborException {
    List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
    if (messageArray.size() != 3) {
      throw new CoseException("Error while decoding Encrypt0Message. Expected 3 items,"
          + "received " + messageArray.size());
    }
    byte[] protectedHeaderBytes = CborUtils.asByteString(messageArray.get(0)).getBytes();
    return Encrypt0Message.builder()
        .withProtectedHeaders(CoseUtils.getProtectedHeadersFromBytes(protectedHeaderBytes))
        .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
        .withCiphertext(CoseUtils.getBytesFromBstrOrNilValue(messageArray.get(2)))
        .build();
  }

  public byte[] getCiphertext() {
    return ciphertext;
  }

  public static Builder builder() {
    return new Builder();
  }
}
