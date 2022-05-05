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

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;

/**
 * Encodes the Sig_Structure as mentioned in COSE RFC section 4.4
 */
public class SignStructure {
  public enum SignatureContext {
    SIGNATURE1("Signature1"),
    SIGNATURE("Signature"),
    COUNTER_SIGNATURE("CounterSignature");

    private final String context;

    SignatureContext(String context) {
      this.context = context;
    }

    String getContext() {
      return this.context;
    }
  }

  private final SignatureContext context;
  private final Map protectedBodyHeaders;
  private final Map protectedSignHeaders;
  private final byte[] externalAad;
  private final byte[] message;

  public SignStructure(SignatureContext context, Map bodyHeaders, Map signHeaders,
      byte[] externalAad, byte[] message) {
    this.context = context;
    this.protectedBodyHeaders = bodyHeaders;
    this.protectedSignHeaders = signHeaders;
    this.externalAad = externalAad;
    this.message = message;
  }

  public byte[] serialize() throws CborException {
    return CborUtils.encode(encode());
  }

  public DataItem encode() throws CborException {
    return CoseUtils.encodeStructure(context.getContext(), protectedBodyHeaders,
        protectedSignHeaders, externalAad, message);
  }
}
