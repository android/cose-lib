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

/**
 * A CBOR Object Signing and Encryption (COSE) KDF context, as defined in go/rfc/8152#section-11.2.
 */
public final class CoseKdfContext {

  private static final int COSE_KDF_CONTEXT_LENGTH = 4;
  private static final int COSE_KDF_CONTEXT_ALG_INDEX = 0;
  private static final int COSE_KDF_CONTEXT_PARTY_U_INDEX = 1;
  private static final int COSE_KDF_CONTEXT_PARTY_V_INDEX = 2;
  private static final int COSE_KDF_CONTEXT_SUPP_PUB_INFO_INDEX = 3;

  private final int alg;
  private final byte[] partyU;
  private final byte[] partyV;
  private final byte[] suppPubInfo;

  public CoseKdfContext(int alg, byte[] partyU, byte[] partyV, byte[] suppPubInfo) {
    this.alg = alg;
    this.partyU = partyU;
    this.partyV = partyV;
    this.suppPubInfo = suppPubInfo;
  }

  public byte[] encode() {
    DataItem coseKdfContext =
        new CborBuilder()
            .addArray()
            .add(alg)
            .add(partyU)
            .add(partyV)
            .add(suppPubInfo)
            .end()
            .build()
            .get(0);
    return CborUtil.encode(coseKdfContext);
  }

  public static CoseKdfContext decode(byte[] data) throws CborException {
    DataItem coseKdfContext = CborUtil.cborToDataItem(data);

    Array array = CborUtil.asArray(coseKdfContext);
    List<DataItem> dataItems = array.getDataItems();

    if (dataItems.size() != COSE_KDF_CONTEXT_LENGTH) {
      throw new CborException(
          String.format(
              "Recipient has the wrong length \nExpected: %s\nActual: %s",
              COSE_KDF_CONTEXT_LENGTH, dataItems.size()));
    }

    int alg = CborUtil.asNumber(dataItems.get(COSE_KDF_CONTEXT_ALG_INDEX));
    byte[] partyU = CborUtil.asByteString(dataItems.get(COSE_KDF_CONTEXT_PARTY_U_INDEX)).getBytes();
    byte[] partyV = CborUtil.asByteString(dataItems.get(COSE_KDF_CONTEXT_PARTY_V_INDEX)).getBytes();
    byte[] suppPubInfo =
        CborUtil.asByteString(dataItems.get(COSE_KDF_CONTEXT_SUPP_PUB_INFO_INDEX)).getBytes();

    return new CoseKdfContext(alg, partyU, partyV, suppPubInfo);
  }

  public int getAlg() {
    return alg;
  }

  public byte[] getPartyU() {
    return partyU;
  }

  public byte[] getPartyV() {
    return partyV;
  }

  public byte[] getSuppPubInfo() {
    return suppPubInfo;
  }
}
