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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Implements COSE_Mac message structure.
 */
public class MacMessage extends CoseMessage {
  protected List<Recipient> recipients;
  private final byte[] message;
  private final byte[] tag;

  MacMessage(byte[] protectedHeaderBytes, Map unprotectedHeaders, byte[] message, byte[] tag,
      List<Recipient> recipients) {
    super(protectedHeaderBytes, unprotectedHeaders);
    this.message = message;
    this.tag = tag;
    this.recipients = recipients;
  }

  static class Builder {
    private byte[] protectedHeaderBytes;
    private Map unprotectedHeaders;
    private byte[] message;
    private byte[] tag;
    private final List<Recipient> recipients;

    Builder() {
      recipients = new ArrayList<>();
    }

    public MacMessage build() throws CoseException {
      if ((protectedHeaderBytes != null) && (unprotectedHeaders != null) && (message != null)
          && (tag != null) && (recipients.size() != 0)) {
        return new MacMessage(protectedHeaderBytes, unprotectedHeaders, message, tag, recipients);
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

    public Builder withMessage(byte[] message) {
      this.message = message;
      return this;
    }

    public Builder withTag(byte[] tag) {
      this.tag = tag;
      return this;
    }

    public Builder withRecipients(List<Recipient> recipients) {
      this.recipients.addAll(recipients);
      return this;
    }

    public Builder withRecipients(Recipient...recipients) {
      return this.withRecipients(Arrays.asList(recipients));
    }

  }

  @Override
  public DataItem encode() throws CoseException {
    ArrayBuilder<CborBuilder> macArrayBuilder = new CborBuilder().addArray();
    macArrayBuilder.add(getProtectedHeaderBytes()).add(getUnprotectedHeaders()).add(message)
        .add(tag);
    ArrayBuilder<ArrayBuilder<CborBuilder>> recipientArrayBuilder = macArrayBuilder.addArray();

    if (recipients == null) {
      throw new CoseException("Error while serializing MacMessage. Recipient field not found.");
    }

    for (Recipient recipient : recipients) {
      recipientArrayBuilder.add(recipient.encode());
    }
    recipientArrayBuilder.end();

    return macArrayBuilder.end().build().get(0);
  }

  public static MacMessage deserialize(byte[] messageBytes) throws CoseException, CborException {
    return decode(CborUtils.decode(messageBytes));
  }

  public static MacMessage decode(DataItem cborMessage) throws CoseException, CborException {
    List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
    if (messageArray.size() != 5) {
      throw new CoseException("Error while decoding MacMessage. Expected 5 items,"
          + "received " + messageArray.size());
    }

    List<Recipient> recipients = new ArrayList<>();
    for (DataItem recipient : CborUtils.asArray(messageArray.get(4)).getDataItems()) {
      Recipient decode = Recipient.decode(recipient);
      recipients.add(decode);
    }
    return MacMessage.builder()
        .withProtectedHeaderBytes(CborUtils.asByteString(messageArray.get(0)).getBytes())
        .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
        .withMessage(CborUtils.asByteString(messageArray.get(2)).getBytes())
        .withTag(CborUtils.asByteString(messageArray.get(3)).getBytes())
        .withRecipients(recipients)
        .build();
  }

  public byte[] getMessage() {
    return message;
  }

  public byte[] getTag() {
    return tag;
  }

  public static Builder builder() {
    return new Builder();
  }
}
