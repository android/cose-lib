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
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import java.util.List;

/** A CBOR Object Signing and Encryption (COSE) recipient, as defined in go/rfc/8152#section-5. */
public final class CoseRecipient {

  // Can be 4, but no nested recipients here.
  private static final int COSE_RECIPIENT_LENGTH = 3;
  private static final int COSE_RECIPIENT_PROTECTED_HEADERS_INDEX = 0;
  private static final int COSE_RECIPIENT_UNPROTECTED_HEADERS_INDEX = 1;
  private static final int COSE_RECIPIENT_CIPHERTEXT_INDEX = 2;

  private final byte[] protectedHeaders;
  private final Map unprotectedHeaders;
  private final byte[] ciphertext;

  public CoseRecipient(byte[] protectedHeaders, Map unprotectedHeaders, byte[] ciphertext) {
    this.protectedHeaders = protectedHeaders;
    this.unprotectedHeaders = unprotectedHeaders;
    this.ciphertext = ciphertext;
  }

  public byte[] encode() {
    DataItem coseRecipient =
        new CborBuilder()
            .addArray()
            .add(protectedHeaders)
            .add(unprotectedHeaders)
            .add(ciphertext)
            .end()
            .build()
            .get(0);
    return CborUtil.encode(coseRecipient);
  }

  public static CoseRecipient decode(byte[] data) throws CborException {
    DataItem coseRecipient = CborUtil.cborToDataItem(data);
    return decode(coseRecipient);
  }

  public static CoseRecipient decode(DataItem data) throws CborException {
    Array recipientArray = CborUtil.asArray(data);
    List<DataItem> dataItems = recipientArray.getDataItems();

    if (dataItems.size() != COSE_RECIPIENT_LENGTH) {
      throw new CborException(
          String.format(
              "Recipient has the wrong length \nExpected: %s\nActual: %s",
              COSE_RECIPIENT_LENGTH, dataItems.size()));
    }

    byte[] protectedHeaders =
        CborUtil.asByteString(dataItems.get(COSE_RECIPIENT_PROTECTED_HEADERS_INDEX)).getBytes();
    Map unprotectedHeaders =
        CborUtil.asMap(dataItems.get(COSE_RECIPIENT_UNPROTECTED_HEADERS_INDEX));
    byte[] ciphertext =
        CborUtil.asByteString(dataItems.get(COSE_RECIPIENT_CIPHERTEXT_INDEX)).getBytes();

    return new CoseRecipient(protectedHeaders, unprotectedHeaders, ciphertext);
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
}
