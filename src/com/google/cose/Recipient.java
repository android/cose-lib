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
 * Implements COSE_Recipient structure.
 */
public class Recipient extends CoseMessage {
  private final byte[] ciphertext;
  private final ImmutableList<Recipient> recipients;

  private Recipient(Map protectedHeaders, Map unprotectedHeaders, byte[] ciphertext,
      ImmutableList<Recipient> recipients) {
    super(protectedHeaders, unprotectedHeaders);
    this.ciphertext = ciphertext;
    this.recipients = recipients;
  }

  public static class Builder {
    private Map protectedHeaders;
    private Map unprotectedHeaders;
    private byte[] ciphertext;
    private ImmutableList<Recipient> recipients;

    public Recipient build() throws CoseException {
      if ((protectedHeaders != null) && (unprotectedHeaders != null)) {
        // recipients is an optional field and ciphertext can be nil, hence we are not checking them
        return new Recipient(protectedHeaders, unprotectedHeaders, ciphertext, recipients);
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
      this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
      return this;
    }

    public Builder withRecipients(Recipient...recipients) {
      return this.withRecipients(Arrays.asList(recipients));
    }

    public Builder withRecipients(List<Recipient> recipients) {
      this.recipients = ImmutableList.copyOf(recipients);
      return this;
    }
  }

  @Override
  public DataItem encode() throws CborException {
    ArrayBuilder<CborBuilder> arrayBuilder = new CborBuilder().addArray();
    arrayBuilder
        .add(CoseUtils.serializeProtectedHeaders(getProtectedHeaders()))
        .add(getUnprotectedHeaders())
        .add(getCiphertext());
    if (recipients != null && !recipients.isEmpty()) {
      ArrayBuilder<ArrayBuilder<CborBuilder>> recipientArrayBuilder = arrayBuilder.addArray();
      for (Recipient recipient : recipients) {
        recipientArrayBuilder.add(recipient.encode());
      }
      recipientArrayBuilder.end();
    }
    return arrayBuilder.end().build().get(0);
  }

  public static Recipient deserialize(byte[] rawBytes) throws CborException, CoseException {
    return decode(CborUtils.decode(rawBytes));
  }

  public static Recipient decode(DataItem cborMessage) throws CborException, CoseException {
    List<DataItem> messageDataItems = CborUtils.asArray(cborMessage).getDataItems();
    List<Recipient> recipients = new ArrayList<>();
    if (messageDataItems.size() == 4) {
      List<DataItem> messageRecipients = CborUtils.asArray(messageDataItems.get(3))
          .getDataItems();
      for (DataItem messageRecipient : messageRecipients) {
        Recipient recipient = Recipient.decode(messageRecipient);
        recipients.add(recipient);
      }
      if (messageRecipients.size() == 0) {
        throw new CoseException("Error while decoding recipient array. Could not find recipients in"
            + " the message.");
      }
    } else if (messageDataItems.size() != 3) {
      throw new CoseException("Error while decoding recipient array. Expected 3 or 4 items, "
          + "recieved " + messageDataItems.size());
    }
    return Recipient.builder()
        .withProtectedHeaders(CoseUtils.asProtectedHeadersMap(messageDataItems.get(0)))
        .withUnprotectedHeaders(CborUtils.asMap(messageDataItems.get(1)))
        .withCiphertext(CoseUtils.getBytesFromBstrOrNilValue(messageDataItems.get(2)))
        .withRecipients(recipients)
        .build();
  }

  public byte[] getCiphertext() {
    return Arrays.copyOf(ciphertext, ciphertext.length);
  }

  public ImmutableList<Recipient> getRecipients() {
    return recipients;
  }

  public static Builder builder() {
    return new Builder();
  }
}
