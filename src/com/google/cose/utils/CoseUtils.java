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
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;

public class CoseUtils {
  private static final String EC_PARAMETER_SPEC = "EC";

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

  public static java.util.Map<Integer, DataItem> getLabelsFromMap(Map keyMap)
      throws CborException {
    final java.util.Map<Integer, DataItem> labels = new HashMap<>();
    for (DataItem item : keyMap.getKeys()) {
      labels.put(CborUtils.asInteger(item), keyMap.get(item));
    }
    return labels;
  }

  /**
   * Returns DataItem from a cbor map based on Integer value.
   * @param cborMap map that has the information.
   * @param value integer to be used as key in the map.
   * @return value in the map corresponding to key
   */
  public static DataItem getValueFromMap(Map cborMap, int value) {
    final Number key;
    if (value >= 0) {
      key = new UnsignedInteger(value);
    } else {
      key = new NegativeInteger(value);
    }
    return cborMap.get(key);
  }

  /**
   * Generates EC2 Private Key from d parameter.
   *
   * Only supports P256 curve currently.
   * @param curve supported curve
   * @param d BigInteger representation for the private key bytes.
   * @return PrivateKey JCA implementation
   * @throws CoseException if unsupported key curve is used.
   */
  public static PrivateKey getEc2PrivateKeyFromCoordinate(int curve, BigInteger d)
      throws CoseException {
    try {
      if (d == null) {
        throw new CoseException("Cannot decode private key. Missing coordinate information.");
      }
      final AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC_PARAMETER_SPEC);
      parameters.init(getEC2ParameterSpecFromCurve(curve));
      final ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
      final ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, ecParameters);
      return KeyFactory.getInstance(EC_PARAMETER_SPEC).generatePrivate(privateKeySpec);
    } catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException e) {
      throw new IllegalStateException("Unexpected error", e);
    }
  }

  /**
   * Generates EC2 Public Key from x and y coordinate values.
   *
   * Only supports P256 curve currently.
   * @param curve supported curve
   * @param x raw bytes for x coordinate.
   * @param y raw bytes for y coordinate.
   * @return PublicKey JCA implementation
   * @throws CoseException if unsupported key curve is used.
   */
  public static PublicKey getEc2PublicKeyFromCoordinates(int curve, BigInteger x, BigInteger y)
      throws CoseException {
    try {
      if (x == null || y == null) {
        // Should not reach here since we should be able to catch it during decoding key.
        throw new CoseException("Cannot decode public key. Missing coordinate information.");
      }
      final AlgorithmParameters params = AlgorithmParameters.getInstance(EC_PARAMETER_SPEC);
      params.init(getEC2ParameterSpecFromCurve(curve));
      final ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);

      final ECPoint ecPoint = new ECPoint(x, y);
      final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, ecParameters);
      return KeyFactory.getInstance(EC_PARAMETER_SPEC).generatePublic(keySpec);
    } catch (final InvalidParameterSpecException | InvalidKeySpecException
        | NoSuchAlgorithmException ex) {
      throw new IllegalStateException("Unexpected error", ex);
    }
  }

  private static ECGenParameterSpec getEC2ParameterSpecFromCurve(int curve) throws CoseException {
    if (curve == Headers.CURVE_EC2_P256) {
      return new ECGenParameterSpec("secp256r1");
    } else if (curve == Headers.CURVE_EC2_P384) {
      return new ECGenParameterSpec("secp384r1");
    } else if (curve == Headers.CURVE_EC2_P521) {
      return new ECGenParameterSpec("secp521r1");
    } else {
      throw new CoseException("Non EC2 key found with curve " + curve);
    }
  }
}
