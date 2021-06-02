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
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.common.collect.ImmutableList;

/** A CBOR Object Signing and Encryption (COSE) key, as defined in go/rfc/8152#section-7. */
public final class CoseKey {

  private static final int COSE_KEY_KTY_KEY = 1;
  private static final int COSE_KEY_KID_KEY = 2;
  private static final int COSE_KEY_ALG_KEY = 3;
  private static final int COSE_KEY_OPS_KEY = 4;
  private static final int COSE_KEY_BASE_IV_KEY = 5;

  private final int keyType;
  private final byte[] keyId;
  private final int alg;
  private final ImmutableList<Integer> keyOps;
  private final byte[] baseIv;

  public CoseKey(int keyType, byte[] keyId, int alg, ImmutableList<Integer> keyOps, byte[] baseIv) {
    this.keyType = keyType;
    this.keyId = keyId;
    this.alg = alg;
    this.keyOps = keyOps;
    this.baseIv = baseIv;
  }

  public byte[] encode() {
    MapBuilder<CborBuilder> keyMapBuilder = new CborBuilder().addMap();
    ArrayBuilder<MapBuilder<CborBuilder>> keyOpsArrayBuilder =
        keyMapBuilder.putArray(COSE_KEY_OPS_KEY);
    for (int ops : keyOps) {
      keyOpsArrayBuilder.add(ops);
    }
    keyOpsArrayBuilder.end();

    DataItem coseKey =
        keyMapBuilder
            .put(COSE_KEY_KTY_KEY, keyType)
            .put(COSE_KEY_KID_KEY, keyId)
            .put(COSE_KEY_ALG_KEY, alg)
            .put(COSE_KEY_BASE_IV_KEY, baseIv)
            .end()
            .build()
            .get(0);
    return CborUtil.encode(coseKey);
  }

  public static CoseKey decode(byte[] data) throws CborException {
    DataItem coseKey = CborUtil.cborToDataItem(data);
    Map keyMap = CborUtil.asMap(coseKey);

    int keyType = CborUtil.asNumber(keyMap.get(new UnsignedInteger(COSE_KEY_KTY_KEY)));
    byte[] keyId =
        CborUtil.asByteString(keyMap.get(new UnsignedInteger(COSE_KEY_KID_KEY))).getBytes();
    int alg = CborUtil.asNumber(keyMap.get(new UnsignedInteger(COSE_KEY_ALG_KEY)));

    Array keyOpsArray = CborUtil.asArray(keyMap.get(new UnsignedInteger(COSE_KEY_OPS_KEY)));
    ImmutableList.Builder<Integer> keyOps = ImmutableList.builder();
    for (DataItem entry : keyOpsArray.getDataItems()) {
      keyOps.add(CborUtil.asNumber(entry));
    }

    byte[] baseIv =
        CborUtil.asByteString(keyMap.get(new UnsignedInteger(COSE_KEY_BASE_IV_KEY))).getBytes();

    return new CoseKey(keyType, keyId, alg, keyOps.build(), baseIv);
  }

  public int getKeyType() {
    return keyType;
  }

  public byte[] getKeyId() {
    return keyId;
  }

  public int getAlg() {
    return alg;
  }

  public ImmutableList<Integer> getKeyOps() {
    return ImmutableList.copyOf(keyOps);
  }

  public byte[] getBaseIv() {
    return baseIv;
  }
}
