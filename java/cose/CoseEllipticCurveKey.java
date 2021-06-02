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
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import java.util.Optional;

/**
 * A CBOR Object Signing and Encryption (COSE) elliptic curve key, as defined in
 * go/rfc/8152#section-13.1.
 */
public final class CoseEllipticCurveKey {

  private static final int COSE_KEY_KTY_KEY = 1;
  private static final int COSE_EC_KEY_CRV_KEY = -1;
  private static final int COSE_EC_KEY_X_KEY = -2;
  private static final int COSE_EC_KEY_D_KEY = -4;

  private static final int COSE_EC_KEY_TYPE = 1;
  private static final int ED25519_CURVE = 6;

  private final byte[] x;
  private final Optional<byte[]> d;

  public CoseEllipticCurveKey(byte[] x, Optional<byte[]> d) {
    this.x = x;
    this.d = d;
  }

  public byte[] encode() {
    MapBuilder<CborBuilder> ecKeyMapBuilder = new CborBuilder().addMap();
    if (d.isPresent()) {
      ecKeyMapBuilder.put(COSE_EC_KEY_D_KEY, d.get());
    }

    DataItem coseEcKey =
        ecKeyMapBuilder
            .put(COSE_KEY_KTY_KEY, COSE_EC_KEY_TYPE)
            .put(COSE_EC_KEY_CRV_KEY, ED25519_CURVE)
            .put(COSE_EC_KEY_X_KEY, x)
            .end()
            .build()
            .get(0);
    return CborUtil.encode(coseEcKey);
  }

  public static CoseEllipticCurveKey decode(byte[] data) throws CborException {
    DataItem coseEcKey = CborUtil.cborToDataItem(data);
    Map keyMap = CborUtil.asMap(coseEcKey);

    byte[] x = CborUtil.asByteString(keyMap.get(new NegativeInteger(COSE_EC_KEY_X_KEY))).getBytes();
    if (keyMap.get(new NegativeInteger(COSE_EC_KEY_D_KEY)) == null) {
      return new CoseEllipticCurveKey(x, Optional.empty());
    }
    return new CoseEllipticCurveKey(
        x,
        Optional.of(
            CborUtil.asByteString(keyMap.get(new NegativeInteger(COSE_EC_KEY_D_KEY))).getBytes()));
  }

  public byte[] getX() {
    return x;
  }

  public Optional<byte[]> getD() {
    return d;
  }
}
