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
 * Implements COSE_Mac message structure.
 */
public class MacMessage extends CoseMessage {
  protected ImmutableList<Recipient> recipients;
  private final byte[] message;
  private final byte[] tag;

  MacMessage(Map protectedHeaders, Map unprotectedHeaders, byte[] message, byte[] tag,
      ImmutableList<Recipient> recipients) {
    super(protectedHeaders, unprotectedHeaders);
    this.message = message;
    this.tag = tag;
    this.recipients = recipients;
  }

  public static class Builder {
    private Map protectedHeaders;
    private Map unprotectedHeaders;
    private byte[] message;
    private byte[] tag;
    private ImmutableList<Recipient> recipients;

    public MacMessage build() throws CoseException {
      if ((protectedHeaders != null) && (unprotectedHeaders != null) && (tag != null)
          && (recipients.size() != 0)) {
        return new MacMessage(protectedHeaders, unprotectedHeaders, message, tag, recipients);
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

    public Builder withTag(byte[] tag) {
      this.tag = tag;
      return this;
    }

    public Builder withRecipients(List<Recipient> recipients) {
      this.recipients = ImmutableList.copyOf(recipients);
      return this;
    }

    public Builder withRecipients(Recipient...recipients) {
      return this.withRecipients(Arrays.asList(recipients));
    }

  }

  @Override
  public DataItem encode() throws CoseException, CborException {
    if (recipients == null) {
      throw new CoseException("Error while serializing MacMessage. Recipient field not found.");
    }

    ArrayBuilder<CborBuilder> macArrayBuilder = new CborBuilder().addArray();
    macArrayBuilder
        .add(CoseUtils.serializeProtectedHeaders(getProtectedHeaders()))
        .add(getUnprotectedHeaders())
        .add(message)
        .add(tag);
    ArrayBuilder<ArrayBuilder<CborBuilder>> recipientArrayBuilder = macArrayBuilder.addArray();

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
        .withProtectedHeaders(CoseUtils.asProtectedHeadersMap(messageArray.get(0)))
        .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
        .withMessage(CoseUtils.getBytesFromBstrOrNilValue(messageArray.get(2)))
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
