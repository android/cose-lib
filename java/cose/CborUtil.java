/*
 * Copyright 2020 Google LLC
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

package cose;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.common.base.VerifyException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;

/** Utility class for CBOR encoding and decoding. */
public final class CborUtil {
  private CborUtil() {}

  /** Encodes a {@link DataItem} into a CBOR byte array (https://tools.ietf.org/html/rfc7049). */
  public static byte[] encode(DataItem dataItem) {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      new CborEncoder(outputStream).encode(dataItem);
      return outputStream.toByteArray();
    } catch (CborException e) {
      // This should never happen.
      throw new IllegalArgumentException(e);
    }
  }

  /** Decodes a CBOR byte array into a {@link DataItem}. */
  public static DataItem cborToDataItem(byte[] data) {
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    try {
      List<DataItem> dataItems = new CborDecoder(bais).decode();
      if (dataItems.size() != 1) {
        throw new VerifyException("Expected 1 item, found " + dataItems.size());
      }
      return dataItems.get(0);
    } catch (CborException e) {
      throw new VerifyException("Error decoding data", e);
    }
  }

  /** Returns the {@link DataItem} as a {@link Map}. */
  public static Map asMap(DataItem dataItem) throws CborException {
    if (dataItem.getMajorType() != MajorType.MAP) {
      throw new CborException(
          String.format("Expected a map, got %s", dataItem.getMajorType().name()));
    }
    return (Map) dataItem;
  }

  /** Returns the {@link DataItem} as an {@link Array}. */
  public static Array asArray(DataItem dataItem) throws CborException {
    if (dataItem.getMajorType() != MajorType.ARRAY) {
      throw new CborException(
          String.format("Expected an array, got %s", dataItem.getMajorType().name()));
    }
    return (Array) dataItem;
  }

  /** Returns the {@link DataItem} as a {@link ByteString}. */
  public static ByteString asByteString(DataItem dataItem) throws CborException {
    if (dataItem.getMajorType() != MajorType.BYTE_STRING) {
      throw new CborException(
          String.format("Expected a byte string, got %s", dataItem.getMajorType().name()));
    }
    return (ByteString) dataItem;
  }

  /** Returns the {@link DataItem} as a {@link int}. */
  public static int asNumber(DataItem dataItem) throws CborException {
    if (dataItem.getMajorType() == MajorType.UNSIGNED_INTEGER) {
      return ((UnsignedInteger) dataItem).getValue().intValue();
    } else if (dataItem.getMajorType() == MajorType.NEGATIVE_INTEGER) {
      return ((NegativeInteger) dataItem).getValue().intValue();
    } else {
      throw new CborException(String.format("Invalid type: %s", dataItem.getMajorType()));
    }
  }
}
