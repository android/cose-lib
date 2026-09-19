/*
 * Copyright 2026 Google LLC
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
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import com.google.cose.utils.Headers;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.util.Arrays;
import java.util.Objects;

/** Abstract class for generic AKP key */
public abstract class AkpKey extends CoseKey {

  public static final String CONSCRYPT_PROVIDER = "Conscrypt";

  protected byte[] publicKeyBytes;

  AkpKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);
    if (getKeyType() != Headers.KEY_TYPE_AKP) {
      throw new CoseException("Expecting KEY_TYPE_AKP (type 7), found type " + getKeyType());
    }
    if (getAlgorithm() == null) {
      throw new CoseException("Algorithm is required for AKP keys.");
    }

    Algorithm algorithm = Algorithm.fromCoseAlgorithmId(getAlgorithm());

    if (algorithm == null || !isAkpAlgorithm(algorithm)) {
      throw new CoseException(
          "Expecting an AKP signing algorithm, found "
              + (algorithm != null ? algorithm.getJavaAlgorithmId() : getAlgorithm()));
    }
    populateKeyFromCbor();
  }

  void populateKeyFromCbor() throws CborException, CoseException {
    if (labels.containsKey(Headers.KEY_PARAMETER_AKP_PUB)) {
      byte[] keyMaterial =
          CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_AKP_PUB)).getBytes();
      if (keyMaterial.length == 0) {
        throw new CoseException("Could not decode public key. Expected key material.");
      }
      publicKeyBytes = keyMaterial;
    } else {
      throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
    }
  }

  void verifyAlgorithmAllowedByKey(Algorithm algorithm) throws CborException, CoseException {
    Map keyMap = CborUtils.asMap(encode());
    DataItem algo = CoseUtils.getValueFromMap(keyMap, Headers.KEY_PARAMETER_ALGORITHM);
    if (algo == null) {
      throw new CoseException("Algorithm is required for AKP keys.");
    }
    if (!algo.equals(algorithm.getCoseAlgorithmId())) {
      throw new CoseException("Algorithm not compatible with AKP key.");
    }
  }

  public byte[] getPublicKeyBytes() {
    return Arrays.copyOf(publicKeyBytes, publicKeyBytes.length);
  }

  /** Recursive builder to build out the AKP key and its subclasses. */
  abstract static class Builder<T extends Builder<T>> extends CoseKey.Builder<T> {
    private byte[] publicKey;

    @Override
    void verifyKeyMaterialPresentAndComplete() throws CoseException {
      if (!isKeyMaterialPresent()) {
        throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
      }
      if (algorithm == null) {
        throw new CoseException("Algorithm is required for AKP keys.");
      }

      if (!isAkpAlgorithm(algorithm)) {
        throw new CoseException(
            "Expecting an AKP signing algorithm, found " + algorithm.getJavaAlgorithmId());
      }
    }

    boolean isKeyMaterialPresent() {
      return publicKey != null && publicKey.length != 0;
    }

    @Override
    protected Map compile() throws CoseException {
      withKeyType(Headers.KEY_TYPE_AKP);

      Map cborKey = super.compile();

      if (publicKey != null && publicKey.length != 0) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_AKP_PUB), new ByteString(publicKey));
      }
      return cborKey;
    }

    @CanIgnoreReturnValue
    public T withPublicKey(byte[] publicKey) {
      this.publicKey = (publicKey != null) ? Arrays.copyOf(publicKey, publicKey.length) : null;
      return self();
    }
  }

  public static boolean isAkpAlgorithm(Algorithm algorithm) {
    return algorithm == Algorithm.SIGNING_ALGORITHM_MLDSA_44
        || algorithm == Algorithm.SIGNING_ALGORITHM_MLDSA_65
        || algorithm == Algorithm.SIGNING_ALGORITHM_MLDSA_87;
  }

  public static boolean isConscryptProvider(String provider) {
    return Objects.equals(provider, CONSCRYPT_PROVIDER);
  }
}
