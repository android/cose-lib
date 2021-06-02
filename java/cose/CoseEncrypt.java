/*
 * Copyright 2020 Google LLC
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

package cose;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.common.collect.ImmutableList;
import java.util.List;

/**
 * A CBOR Object Signing and Encryption (COSE) encrypt object, as defined in
 * go/rfc/8152#section-5.2.
 */
public final class CoseEncrypt {

  private static final int COSE_ENCRYPT_LENGTH = 4;
  private static final int COSE_ENCRYPT_PROTECTED_HEADERS_INDEX = 0;
  private static final int COSE_ENCRYPT_UNPROTECTED_HEADERS_INDEX = 1;
  private static final int COSE_ENCRYPT_CIPHERTEXT_INDEX = 2;
  private static final int COSE_ENCRYPT_RECIPIENTS_INDEX = 3;

  private final byte[] protectedHeaders;
  private final Map unprotectedHeaders;
  private final byte[] ciphertext;
  // List of CBOR encoded recipient
  private final List<byte[]> recipients;

  public CoseEncrypt(
      byte[] protectedHeaders, Map unprotectedHeaders, byte[] ciphertext, List<byte[]> recipients) {
    this.protectedHeaders = protectedHeaders;
    this.unprotectedHeaders = unprotectedHeaders;
    this.ciphertext = ciphertext;
    this.recipients = recipients;
  }

  public byte[] encode() {
    ArrayBuilder<CborBuilder> encryptArrayBuilder = new CborBuilder().addArray();
    encryptArrayBuilder.add(protectedHeaders).add(unprotectedHeaders).add(ciphertext);
    ArrayBuilder<ArrayBuilder<CborBuilder>> recipientArrayBuilder = encryptArrayBuilder.addArray();

    for (byte[] recipient : recipients) {
      recipientArrayBuilder.add(recipient);
    }
    recipientArrayBuilder.end();

    return CborUtil.encode(encryptArrayBuilder.end().build().get(0));
  }

  public static CoseEncrypt decode(byte[] data) throws CborException {
    DataItem coseEncrypt = CborUtil.cborToDataItem(data);

    Array array = CborUtil.asArray(coseEncrypt);
    List<DataItem> dataItems = array.getDataItems();

    if (dataItems.size() != COSE_ENCRYPT_LENGTH) {
      throw new CborException(
          String.format(
              "Recipient has the wrong length \nExpected: %s\nActual: %s",
              COSE_ENCRYPT_LENGTH, dataItems.size()));
    }

    byte[] protectedHeaders =
        CborUtil.asByteString(dataItems.get(COSE_ENCRYPT_PROTECTED_HEADERS_INDEX)).getBytes();
    Map unprotectedHeaders = CborUtil.asMap(dataItems.get(COSE_ENCRYPT_UNPROTECTED_HEADERS_INDEX));
    byte[] ciphertext =
        CborUtil.asByteString(dataItems.get(COSE_ENCRYPT_CIPHERTEXT_INDEX)).getBytes();

    Array recipientArray = CborUtil.asArray(dataItems.get(COSE_ENCRYPT_RECIPIENTS_INDEX));

    ImmutableList.Builder<byte[]> builder = ImmutableList.builder();
    for (DataItem entry : recipientArray.getDataItems()) {
      builder.add(CborUtil.asByteString(entry).getBytes());
    }

    return new CoseEncrypt(protectedHeaders, unprotectedHeaders, ciphertext, builder.build());
  }

  public byte[] getProtectedHeaders() {
    return protectedHeaders;
  }

  public Map getUnprotectedHeaders() {
    return unprotectedHeaders;
  }

  public byte[] getCiphertext() {
    return ciphertext;
  }

  public ImmutableList<byte[]> getRecipients() {
    return ImmutableList.copyOf(recipients);
  }
}
