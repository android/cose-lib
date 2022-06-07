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

package com.google.cose;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import com.google.cose.utils.Headers;

/**
 * Implements the base class for COSE Message structure to be implemented for other message types.
 */
public abstract class CoseMessage {
  private final Map protectedHeaders;
  private final Map unprotectedHeaders;

  CoseMessage(Map protectedHeaders, Map unprotectedHeaders) {
    this.protectedHeaders = protectedHeaders;
    this.unprotectedHeaders = unprotectedHeaders;
  }

  // TODO: Add counter signature support

  public abstract DataItem encode() throws CborException, CoseException;

  public byte[] serialize() throws CborException, CoseException {
    return CborUtils.encode(encode());
  }

  public Map getProtectedHeaders() {
    return protectedHeaders;
  }

  public Map getUnprotectedHeaders() {
    return unprotectedHeaders;
  }

  public DataItem findAttributeInHeaders(int headerIndex) throws CoseException {
    DataItem item = CoseUtils.getValueFromMap(protectedHeaders, headerIndex);
    if (item != null) {
      return item;
    }
    item = CoseUtils.getValueFromMap(unprotectedHeaders, headerIndex);
    if (item == null) {
      throw new CoseException("Could not find header " + headerIndex + " in the message.");
    }
    return item;
  }
}
