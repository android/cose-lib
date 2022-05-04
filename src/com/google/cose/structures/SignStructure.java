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
 * Encodes the Sig_Structure as mentioned in COSE RFC section 4.4
 */
public class SignStructure {
  private final String context;
  private final Map protectedBodyHeaders;
  private final Map protectedSignHeaders;
  private final byte[] externalAad;
  private final byte[] message;

  public SignStructure(String context, Map bodyHeaders, Map signHeaders, byte[] externalAad,
      byte[] message) {
    this.context = context;
    this.protectedBodyHeaders = bodyHeaders;
    this.protectedSignHeaders = signHeaders;
    this.externalAad = externalAad;
    this.message = message;
  }

  public byte[] serialize() {
    return CborUtils.encode(encode());
  }

  public DataItem encode() {
    return CborUtils.encodeStructure(context, protectedBodyHeaders, protectedSignHeaders,
        externalAad, message);
  }
}
