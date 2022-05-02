package com.google.cose.utils;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
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
  public static DataItem decode(final byte[] data) {
    final ByteArrayInputStream bais = new ByteArrayInputStream(data);
    try {
      final List<DataItem> dataItems = new CborDecoder(bais).decode();
      if (dataItems.size() != 1) {
        throw new CoseException("Byte stream cannot be decoded properly. Expected 1 item, found "
            + dataItems.size());
      }
      return dataItems.get(0);
    } catch (final CborException ex) {
      throw new CoseException("Error decoding data", ex);
    }
  }

  /**
   * Converts CBOR data item into byte encoding.
   * @param dataItem DataItem cbor object
   * @return encoded bytes
   */
  public static byte[] encode(final DataItem dataItem) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    CborEncoder encoder = new CborEncoder(baos);
    try {
      encoder.encode(dataItem);
    } catch (final CborException ex) {
      throw new CoseException("Error encoding data", ex);
    }
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
   * Returns DataItem from a cbor map based on Integer index.
   * @param cborMap map that has the information.
   * @param index integer index to be used as key in the map.
   * @return value in the map corresponding to key
   */
  public static DataItem getValueFromMap(final Map cborMap, final int index) {
    final Number key;
    if (index >= 0) {
      key = new UnsignedInteger(index);
    } else {
      key = new NegativeInteger(index);
    }
    return cborMap.get(key);
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
    } else if (dataItem.getMajorType() == MajorType.NEGATIVE_INTEGER) {
      return ((NegativeInteger) dataItem).getValue().intValue();
    } else {
      throw new CborException(String.format("Invalid type: %s", dataItem.getMajorType()));
    }
  }

  public static DataItem encodeStructure(String context, Map protectedBodyHeaders,
      Map protectedSignHeaders, byte[] externalAad, byte[] payload) {
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
}
