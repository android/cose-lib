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

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.SimpleValueType;
import co.nstant.in.cbor.model.Special;
import co.nstant.in.cbor.model.SpecialType;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;

/**
 * This class contains utility functions for converting bytes to CBOR objects.
 */
public class CborUtils {

  /**
   * Decodes cbor byte encoding into a CBOR data item.
   * @param data byte array in cbor format.
   * @return DataItem cbor object
   */
  public static DataItem decode(final byte[] data) throws CborException {
    final ByteArrayInputStream bais = new ByteArrayInputStream(data);
    final List<DataItem> dataItems = new CborDecoder(bais).decode();
    if (dataItems.size() != 1) {
      throw new CborException("Byte stream cannot be decoded properly. Expected 1 item, found "
          + dataItems.size());
    }
    return dataItems.get(0);
  }

  /**
   * Converts CBOR data item into byte encoding.
   * @param dataItem DataItem cbor object
   * @return encoded bytes
   */
  public static byte[] encode(final DataItem dataItem) throws CborException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    CborEncoder encoder = new CborEncoder(baos);
    encoder.encode(dataItem);
    return baos.toByteArray();
  }

  /**
   * Returns the {@link DataItem} as a {@link Map}.
   * @param dataItem cborObject to be converted to Map.
   * @return Map object
   */
  public static Map asMap(final DataItem dataItem) throws CborException {
    if (dataItem.getMajorType() != MajorType.MAP) {
      throw new CborException(
          String.format("Expected a map, got %s", dataItem.getMajorType().name()));
    }
    return (Map) dataItem;
  }

  /**
   * Returns the {@link DataItem} as an {@link Array}.
   * @param dataItem cborObject to be converted to Array.
   * @return Array object
   */
  public static Array asArray(final DataItem dataItem) throws CborException {
    if (dataItem.getMajorType() != MajorType.ARRAY) {
      throw new CborException(
          String.format("Expected an array, got %s", dataItem.getMajorType().name()));
    }
    return (Array) dataItem;
  }

  public static Array asArray(final DataItem dataItem, final int length,
      final String semanticName) throws CborException {
    Array item = asArray(dataItem);
    if (item.getDataItems().size() != length) {
      throw new CborException(String.format("Expected %s to be of size %d, recieved %d",
          semanticName, length, item.getDataItems().size()));
    }
    return item;
  }

  /**
   * Returns the {@link DataItem} as an {@link Array}.
   * @param dataItem cborObject to be converted to Array.
   * @return Array object
   */
  public static List<DataItem> getDataItems(final DataItem dataItem) throws CborException {
    return asArray(dataItem).getDataItems();
  }

  /**
   * Returns the {@link DataItem} as a {@link ByteString}.
   * @param dataItem cborObject to be converted to ByteString.
   * @return ByteString object
   */
  public static ByteString asByteString(final DataItem dataItem) throws CborException {
    if (dataItem.getMajorType() != MajorType.BYTE_STRING) {
      throw new CborException(
          String.format("Expected a byte string, got %s", dataItem.getMajorType().name()));
    }
    return (ByteString) dataItem;
  }

  /**
   * Returns the {@link DataItem} as a byte array.
   * @param dataItem cborObject to get bytes from.
   * @return byte array
   */
  public static byte[] getBytes(final DataItem dataItem) throws CborException {
    return asByteString(dataItem).getBytes();
  }

  /**
   * Returns the {@link DataItem} as a {@link UnicodeString}.
   * @param dataItem cborObject to be converted to UnicodeString.
   * @return UnicodeString object
   */
  public static UnicodeString asUnicodeString(final DataItem dataItem) throws CborException {
    if (dataItem.getMajorType() != MajorType.UNICODE_STRING) {
      throw new CborException(
          String.format("Expected a unicode string, got %s", dataItem.getMajorType().name()));
    }
    return (UnicodeString) dataItem;
  }

  /**
   * Returns the {@link DataItem} as a String.
   * @param dataItem cborObject to be converted to string.
   * @return String
   */
  public static String getString(final DataItem dataItem) throws CborException {
    return asUnicodeString(dataItem).getString();
  }

  /**
   * Returns DataItem as integer.
   * @param dataItem UnsignedInteger or NegativeInteger
   * @return integer value of the DataItem
   * @throws CborException if dataItem is neither UnsignedInteger not NegativeInteger
   */
  public static int asInteger(final DataItem dataItem) throws CborException {
    if (dataItem.getMajorType() == MajorType.UNSIGNED_INTEGER) {
      return ((UnsignedInteger) dataItem).getValue().intValue();
    }
    if (dataItem.getMajorType() == MajorType.NEGATIVE_INTEGER) {
      return ((NegativeInteger) dataItem).getValue().intValue();
    }
    throw new CborException(
        String.format("Expected a number, got %s", dataItem.getMajorType()));
  }

  /**
   * Checks if a given DataItem is a CBOR representation for null.
   * @param item DataItem object
   * @return true if the item represents NULL
   */
  public static boolean isNull(final DataItem item) {
    return (item.getMajorType() == MajorType.SPECIAL)
        && ((Special) item).getSpecialType() == SpecialType.SIMPLE_VALUE
        && ((SimpleValue) item).getSimpleValueType() == SimpleValueType.NULL;
  }

  // Avoiding instantiation of the class
  private CborUtils() {}
}
