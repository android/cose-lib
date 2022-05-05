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

package com.google.cose.utils;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;

public class CoseUtils {
  public static DataItem encodeStructure(String context, Map protectedBodyHeaders,
      Map protectedSignHeaders, byte[] externalAad, byte[] payload) throws CborException {
    ArrayBuilder<CborBuilder> arrayBuilder = new CborBuilder().addArray();
    arrayBuilder.add(context);
    if (protectedBodyHeaders.getKeys().size() == 0) {
      arrayBuilder.add(new byte[0]);
    } else {
      arrayBuilder.add(CborUtils.encode(protectedBodyHeaders));
    }
    if (protectedSignHeaders != null) {
      if (protectedSignHeaders.getKeys().size() == 0) {
        arrayBuilder.add(new byte[0]);
      } else {
        arrayBuilder.add(CborUtils.encode(protectedSignHeaders));
      }
    }
    arrayBuilder.add(externalAad);
    if (payload != null) {
      arrayBuilder.add(payload);
    }
    return arrayBuilder.end().build().get(0);
  }
}
