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
 * Implements COSE_Encrpyt message structure.
 */
public class EncryptMessage extends CoseMessage {
  private final byte[] ciphertext;
  private final ImmutableList<Recipient> recipients;

  EncryptMessage(Map protectedHeaders, Map unprotectedHeaders, byte[] ciphertext,
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

    public EncryptMessage build() throws CoseException {
      if ((protectedHeaders != null) && (unprotectedHeaders != null) && (recipients.size() != 0)) {
        return new EncryptMessage(protectedHeaders, unprotectedHeaders, ciphertext, recipients);
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

    public Builder withRecipients(List<Recipient> recipients) {
      this.recipients = ImmutableList.copyOf(recipients);
      return this;
    }

    public Builder withRecipients(Recipient...recipients) {
      return this.withRecipients(Arrays.asList(recipients));
    }
  }

  @Override
  public DataItem encode() throws CborException, CoseException {
    ArrayBuilder<CborBuilder> encryptArrayBuilder = new CborBuilder().addArray();
    encryptArrayBuilder
        .add(CoseUtils.serializeProtectedHeaders(getProtectedHeaders()))
        .add(getUnprotectedHeaders())
        .add(ciphertext);
    ArrayBuilder<ArrayBuilder<CborBuilder>> recipientArrayBuilder = encryptArrayBuilder.addArray();

    if (recipients == null) {
      throw new CoseException("Error while serializing EncryptMessage. Recipient field not found.");
    }

    for (Recipient recipient : recipients) {
      recipientArrayBuilder.add(recipient.encode());
    }
    recipientArrayBuilder.end();

    return encryptArrayBuilder.end().build().get(0);
  }

  public static EncryptMessage deserialize(byte[] messageBytes) throws CborException, CoseException {
    return decode(CborUtils.decode(messageBytes));
  }

  public static EncryptMessage decode(DataItem cborMessage) throws CborException, CoseException {
    List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
    if (messageArray.size() != 4) {
      throw new CoseException("Error while decoding EncryptMessage. Expected 4 items,"
          + "received " + messageArray.size());
    }

    List<Recipient> recipients = new ArrayList<>();
    for (DataItem recipient : CborUtils.asArray(messageArray.get(3)).getDataItems()) {
      Recipient decode = Recipient.decode(recipient);
      recipients.add(decode);
    }

    return EncryptMessage.builder()
        .withProtectedHeaders(CoseUtils.asProtectedHeadersMap(messageArray.get(0)))
        .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
        .withCiphertext(CoseUtils.getBytesFromBstrOrNilValue(messageArray.get(2)))
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
