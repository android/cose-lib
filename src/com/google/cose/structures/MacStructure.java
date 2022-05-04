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

package com.google.cose.structures;

import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.utils.CborUtils;

/**
 * Encodes the MAC_Structure as mentioned in COSE RFC section 6.3
 */
public class MacStructure {
  private final String context;
  private final Map protectedHeaders;
  private final byte[] externalAad;
  private final byte[] message;

  public MacStructure(String context, Map headers, byte[] externalAad, byte[] message) {
    this.context = context;
    this.protectedHeaders = headers;
    this.externalAad = externalAad;
    this.message = message;
  }

  public byte[] serialize() {
    return CborUtils.encode(encode());
  }

  public DataItem encode() {
    return CborUtils.encodeStructure(context, protectedHeaders, null, externalAad, message);
  }
}
