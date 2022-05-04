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
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Implements COSE_Recipient structure.
 */
public class Recipient extends CoseMessage {
  private final byte[] ciphertext;
  private final List<Recipient> recipients;

  private Recipient(byte[] protectedHeaderBytes, Map unprotectedHeaders, byte[] ciphertext,
      List<Recipient> recipients) {
    super(protectedHeaderBytes, unprotectedHeaders);
    this.ciphertext = ciphertext;
    this.recipients = recipients;
  }

  static class Builder {
    private byte[] protectedHeaderBytes;
    private Map unprotectedHeaders;
    private byte[] ciphertext;
    private final List<Recipient> recipients;

    Builder() {
      this.recipients = new ArrayList<>();
    }

    public Recipient build() throws CoseException {
      if ((protectedHeaderBytes != null) && (unprotectedHeaders != null) && (ciphertext != null)) {
        // recipients is an optional field and hence we are not checking that.
        return new Recipient(protectedHeaderBytes, unprotectedHeaders, ciphertext, recipients);
      } else {
        throw new CoseException("Some fields are missing.");
      }
    }

    public Builder withProtectedHeaderBytes(byte[] protectedHeaderBytes) {
      this.protectedHeaderBytes = protectedHeaderBytes;
      return this;
    }

    public Builder withProtectedHeaders(Map protectedHeaders) throws CoseException, CborException {
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

    public Builder withCiphertext(byte[] ciphertext) {
      this.ciphertext = ciphertext;
      return this;
    }

    public Builder withRecipients(Recipient...recipients) {
      return this.withRecipients(Arrays.asList(recipients));
    }

    public Builder withRecipients(List<Recipient> recipients) {
      this.recipients.addAll(recipients);
      return this;
    }
  }

  @Override
  public DataItem encode() {
    ArrayBuilder<CborBuilder> arrayBuilder = new CborBuilder().addArray();
    arrayBuilder.add(getProtectedHeaderBytes()).add(getUnprotectedHeaders()).add(getCiphertext());
    if (recipients != null && !recipients.isEmpty()) {
      ArrayBuilder<ArrayBuilder<CborBuilder>> recipientArrayBuilder = arrayBuilder.addArray();
      for (Recipient recipient : recipients) {
        recipientArrayBuilder.add(recipient.encode());
      }
      recipientArrayBuilder.end();
    }
    return arrayBuilder.end().build().get(0);
  }

  public static Recipient deserialize(byte[] rawBytes) throws CoseException, CborException {
    return decode(CborUtils.decode(rawBytes));
  }

  public static Recipient decode(DataItem cborMessage) throws CoseException, CborException {
    List<DataItem> messageDataItems = CborUtils.asArray(cborMessage).getDataItems();
    DataItem protectedHeader = messageDataItems.get(0);
    Map unprotectedHeaders = CborUtils.asMap(messageDataItems.get(1));
    ByteString ciphertext = CborUtils.asByteString(messageDataItems.get(2));
    List<Recipient> recipients = new ArrayList<>();
    if (messageDataItems.size() == 4) {
      List<DataItem> messageRecipients = CborUtils.asArray(messageDataItems.get(3))
          .getDataItems();
      for (DataItem messageRecipient : messageRecipients) {
        Recipient recipient = Recipient.decode(messageRecipient);
        recipients.add(recipient);
      }
    } else if (messageDataItems.size() != 3) {
      throw new CoseException("Error while decoding recipient array. Expected 3 ");
    }
    return Recipient.builder()
        .withProtectedHeaderBytes(CborUtils.asByteString(protectedHeader).getBytes())
        .withUnprotectedHeaders(unprotectedHeaders)
        .withCiphertext(ciphertext.getBytes())
        .withRecipients(recipients)
        .build();
  }

  public byte[] getCiphertext() {
    return ciphertext;
  }

  public List<Recipient> getRecipients() {
    return recipients;
  }

  public static Builder builder() {
    return new Builder();
  }
}
