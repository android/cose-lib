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
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.DataItem;
import java.util.List;
import java.util.Optional;

/** Utility class for COSE encoding and decoding. */
public final class CoseUtil {

  private static final int COSE_GENERIC_HEADER_ALG_KEY = 1;
  private static final int COSE_GENERIC_HEADER_CRIT_KEY = 2;
  private static final int COSE_GENERIC_HEADER_CONTENT_TYPE_KEY = 3;
  private static final int COSE_GENERIC_HEADER_KID_KEY = 4;
  private static final int COSE_GENERIC_HEADER_IV_KEY = 5;
  private static final int COSE_GENERIC_HEADER_PARTIAL_IV_KEY = 6;
  private static final int COSE_GENERIC_HEADER_COUNTER_SIGNATURE_KEY = 7;

  public static DataItem buildUnprotectedHeader(
      Optional<Integer> alg,
      Optional<List<Integer>> labels,
      Optional<Integer> contentType,
      Optional<byte[]> kid,
      Optional<byte[]> iv,
      Optional<byte[]> partialIv,
      Optional<byte[]> coseSignature) {

    MapBuilder<CborBuilder> headerMapBuilder = new CborBuilder().addMap();

    if (alg.isPresent()) {
      headerMapBuilder.put(COSE_GENERIC_HEADER_ALG_KEY, alg.get());
    }

    if (labels.isPresent()) {
      ArrayBuilder<MapBuilder<CborBuilder>> labelsArrayBuilder =
          headerMapBuilder.putArray(COSE_GENERIC_HEADER_CRIT_KEY);
      for (int label : labels.get()) {
        labelsArrayBuilder.add(label);
      }
      labelsArrayBuilder.end();
    }

    if (contentType.isPresent()) {
      headerMapBuilder.put(COSE_GENERIC_HEADER_CONTENT_TYPE_KEY, contentType.get());
    }

    if (kid.isPresent()) {
      headerMapBuilder.put(COSE_GENERIC_HEADER_KID_KEY, kid.get());
    }

    if (iv.isPresent()) {
      headerMapBuilder.put(COSE_GENERIC_HEADER_IV_KEY, iv.get());
    }

    if (partialIv.isPresent()) {
      headerMapBuilder.put(COSE_GENERIC_HEADER_PARTIAL_IV_KEY, partialIv.get());
    }

    if (coseSignature.isPresent()) {
      headerMapBuilder.put(COSE_GENERIC_HEADER_COUNTER_SIGNATURE_KEY, coseSignature.get());
    }

    return headerMapBuilder.end().build().get(0);
  }

  private CoseUtil() {}
}
