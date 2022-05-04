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
 * Encodes the Enc_Structure as mentioned in COSE RFC section 5.3
 */
public class EncryptStructure {
  public enum EncryptionContext {
    ENCRYPT0("Encrypt0"),
    ENCRYPT("Encrypt"),
    ENCRYPT_RECIPIENT("Enc_Recipient"),
    MAC_RECIPIENT("Mac_Recipient"),
    RECIPIENT_RECIPIENT("Rec_Recipient");

    private final String context;

    EncryptionContext(String context) {
      this.context = context;
    }

    String getContext() {
      return this.context;
    }
  }

  private final EncryptionContext context;
  private final Map protectedHeaders;
  private final byte[] externalAad;

  public EncryptStructure(EncryptionContext context, Map headers, byte[] externalAad) {
    this.context = context;
    this.protectedHeaders = headers;
    this.externalAad = externalAad;
  }

  public byte[] serialize() {
    return CborUtils.encode(encode());
  }

  public DataItem encode() {
    return CborUtils.encodeStructure(context.getContext(), protectedHeaders, null, externalAad, null);
  }
}
