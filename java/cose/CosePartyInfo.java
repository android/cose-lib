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
import java.util.List;

/** A CBOR Object Signing and Encryption (COSE) PartyInfo, needed by COSE KDF Context. */
public final class CosePartyInfo {

  private static final int COSE_PARTY_LENGTH = 3;
  private static final int COSE_PARTY_IDENTITY_INDEX = 0;
  private static final int COSE_PARTY_NONCE_INDEX = 1;
  private static final int COSE_PARTY_OTHER_INDEX = 2;

  private final byte[] identity;
  private final byte[] nonce;
  private final byte[] other;

  public CosePartyInfo(byte[] identity, byte[] nonce, byte[] other) {
    this.identity = identity;
    this.nonce = nonce;
    this.other = other;
  }

  public byte[] encode() {
    DataItem coseParty =
        new CborBuilder().addArray().add(identity).add(nonce).add(other).end().build().get(0);
    return CborUtil.encode(coseParty);
  }

  public static CosePartyInfo decode(byte[] data) throws CborException {
    DataItem coseParty = CborUtil.cborToDataItem(data);

    Array array = CborUtil.asArray(coseParty);
    List<DataItem> dataItems = array.getDataItems();

    if (dataItems.size() != COSE_PARTY_LENGTH) {
      throw new CborException(
          String.format(
              "Party info has the wrong length \nExpected: %s\nActual: %s",
              COSE_PARTY_LENGTH, dataItems.size()));
    }

    byte[] identity = CborUtil.asByteString(dataItems.get(COSE_PARTY_IDENTITY_INDEX)).getBytes();
    byte[] nonce = CborUtil.asByteString(dataItems.get(COSE_PARTY_NONCE_INDEX)).getBytes();
    byte[] other = CborUtil.asByteString(dataItems.get(COSE_PARTY_OTHER_INDEX)).getBytes();

    return new CosePartyInfo(identity, nonce, other);
  }

  public byte[] getIdentity() {
    return identity;
  }

  public byte[] getNonce() {
    return nonce;
  }

  public byte[] getOther() {
    return other;
  }
}
