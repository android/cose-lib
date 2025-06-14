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
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import com.google.cose.utils.Headers;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Abstract class for COSE_Key which would be used for implementing keys for other
 * functionalities like SigningKey, EncryptionKey and MacKey. We can implement more keys once we
 * know of use cases.
 */
public abstract class CoseKey {
  private final byte[] keyId;
  private final int keyType;
  private final Integer algorithm;
  private final byte[] baseIv;
  protected ImmutableMap<Integer, DataItem> labels;
  protected ImmutableList<Integer> operations;

  private final DataItem cborKey;

  public CoseKey(DataItem cborKey) throws CborException {
    if (cborKey == null) {
      throw new IllegalArgumentException("cborKey cannot be null.");
    }
    this.cborKey = cborKey;

    final Map keyMap = CborUtils.asMap(cborKey);
    final DataItem type = CoseUtils.getValueFromMap(keyMap, Headers.KEY_PARAMETER_KEY_TYPE);

    keyType = CborUtils.asInteger(type);
    labels = CoseUtils.getLabelsFromMap(keyMap);

    final DataItem keyId = CoseUtils.getValueFromMap(keyMap, Headers.KEY_PARAMETER_KEY_ID);
    this.keyId = (keyId != null) ? CborUtils.getBytes(keyId) : null;

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

  public DataItem encode() {
    return cborKey;
  }

  /**
   * Implements the cose to byte serialization.
   * @return byte array representation of the key
   */
  public byte[] serialize() throws CborException {
    return CborUtils.encode(cborKey);
  }

  public byte[] getKeyId() {
    return keyId;
  }

  public Integer getAlgorithm() {
    return algorithm;
  }

  public int getKeyType() {
    return keyType;
  }

  public ImmutableMap<Integer, DataItem> getLabels() {
    return labels;
  }

  public byte[] getBaseIv() {
    return baseIv;
  }

  void verifyOperationAllowedByKey(int keyOperation) throws CoseException {
    if (operations != null && !operations.contains(keyOperation)) {
      throw new CoseException("Key does not allow this operation.");
    }
  }

  void verifyAlgorithmMatchesKey(Algorithm algorithm) throws CborException, CoseException {
    if (this.algorithm != null
        && this.algorithm != CborUtils.asInteger(algorithm.getCoseAlgorithmId())) {
      throw new CoseException("Incompatible key algorithm.");
    }
  }

  public static CoseKey generateKey(Algorithm algorithm) throws CborException, CoseException {
    switch (algorithm) {
      case SIGNING_ALGORITHM_EDDSA:
        return OkpSigningKey.generateKey();
      case SIGNING_ALGORITHM_ECDSA_SHA_256:
      case SIGNING_ALGORITHM_ECDSA_SHA_384:
      case SIGNING_ALGORITHM_ECDSA_SHA_512:
        return Ec2SigningKey.generateKey(algorithm);
      default:
        throw new CoseException("Unknown Key Type specified: " + algorithm.getJavaAlgorithmId());
    }
  }

  abstract static class Builder<T extends Builder<T>> {
    private int keyType;
    private byte[] keyId;
    private Algorithm algorithm;
    private final Set<Integer> operations = new LinkedHashSet<>();
    private byte[] baseIv;

    abstract T self();
    abstract CoseKey build() throws CborException, CoseException;
    abstract void verifyKeyMaterialPresentAndComplete() throws CoseException;

    protected Map compile() throws CoseException {
      verifyKeyMaterialPresentAndComplete();

      Map cborKey = new Map();
      cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_TYPE),
          new UnsignedInteger(keyType));

      if (keyId != null) {
        cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_ID), new ByteString(keyId));
      }
      if (algorithm != null) {
        cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_ALGORITHM),
            algorithm.getCoseAlgorithmId());
      }
      if (operations.size() != 0) {
        Array keyOperations = new Array();
        for (int operation : operations) {
          keyOperations.add(new UnsignedInteger(operation));
        }
        cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_OPERATIONS), keyOperations);
      }
      if (baseIv != null) {
        cborKey.put(new UnsignedInteger(Headers.KEY_PARAMETER_BASE_IV),
            new ByteString(baseIv));
      }
      return cborKey;
    }

    public T copyFrom(CoseKey key) {
      keyType = key.keyType;
      keyId = key.keyId;
      algorithm = (key.algorithm == null) ? null : Algorithm.fromCoseAlgorithmId(key.algorithm);
      operations.clear();
      if (key.operations != null) {
        operations.addAll(key.operations);
      }
      baseIv = key.baseIv;
      return self();
    }

    public T withKeyType(int keyType) {
      this.keyType = keyType;
      return self();
    }

    public T withKeyId(byte[] keyId) {
      this.keyId = keyId;
      return self();
    }

    public T withAlgorithm(Algorithm algorithm) {
      this.algorithm = algorithm;
      return self();
    }

    public T withOperations(Integer...operations) throws CoseException {
      this.operations.addAll(Arrays.asList(operations));
      return self();
    }

    public T withBaseIv(byte[] baseIv) {
      this.baseIv = baseIv;
      return self();
    }
  }
}
