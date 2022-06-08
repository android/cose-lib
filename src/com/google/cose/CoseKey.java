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
import com.google.common.collect.ImmutableList;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import com.google.cose.utils.Headers;
import java.util.ArrayList;
import java.util.List;

/**
 * Abstract class for COSE_Key which would be used for implementing keys for other
 * functionalities like SigningKey, EncryptionKey and MacKey. We can implement more keys once we
 * know of use cases.
 */
public abstract class CoseKey {
  protected String keyId;
  protected int keyType;
  protected Integer algorithm;
  protected ImmutableList<Integer> operations;
  protected byte[] baseIv;
  protected java.util.Map<Integer, DataItem> labels;

  protected final DataItem cborKey;

  public CoseKey(DataItem cborKey) throws CborException {
    this.cborKey = cborKey;
    if (cborKey != null) {
      populate();
    }
  }

  /**
   * Implements the cose to byte serialization.
   * @return byte array representation of the key
   */
  byte[] serialize() throws CborException {
    return CborUtils.encode(cborKey);
  }

  private void populate() throws CborException {
    final Map keyMap = CborUtils.asMap(cborKey);
    final DataItem type = CoseUtils.getValueFromMap(keyMap, Headers.KEY_PARAMETER_KEY_TYPE);

    keyType = CborUtils.asInteger(type);
    labels = CoseUtils.getLabelsFromMap(keyMap);

    final DataItem keyId = CoseUtils.getValueFromMap(keyMap, Headers.KEY_PARAMETER_KEY_ID);
    this.keyId = (keyId != null) ? new String(CborUtils.asByteString(keyId).getBytes()) : null;

    final DataItem algorithm = CoseUtils.getValueFromMap(keyMap, Headers.KEY_PARAMETER_ALGORITHM);
    this.algorithm = (algorithm != null) ? CborUtils.asInteger(algorithm) : null;

    final DataItem ops = CoseUtils.getValueFromMap(keyMap, Headers.KEY_PARAMETER_OPERATIONS);
    if (ops == null) {
      this.operations = null;
    } else {
      List<Integer> operations = new ArrayList<>();
      for (DataItem dataItem : CborUtils.asArray(ops).getDataItems()) {
        operations.add(CborUtils.asInteger(dataItem));
      }
      this.operations = ImmutableList.copyOf(operations);
    }

    final DataItem baseIv = CoseUtils.getValueFromMap(keyMap, Headers.KEY_PARAMETER_BASE_IV);
    this.baseIv = (baseIv != null) ? CborUtils.asByteString(baseIv).getBytes() : null;
  }

  public String getKeyId() {
    return keyId;
  }

  public int getKeyType() {
    return keyType;
  }

  public java.util.Map<Integer, DataItem> getLabels() {
    return labels;
  }

  void verifyOperationAllowedByKey(int keyOperation) throws CoseException {
    if (operations != null && operations.contains(keyOperation)) {
      throw new CoseException("Key does not allow this operation.");
    }
  }

  void verifyAlgorithmMatchesKey(Algorithm algorithm) throws CborException, CoseException {
    if (this.algorithm != null &&
        this.algorithm != CborUtils.asInteger(algorithm.getCoseAlgorithmId())) {
      throw new CoseException("Incompatible key algorithm.");
    }
  }
}
