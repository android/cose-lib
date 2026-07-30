package com.google.cose.utils;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import org.junit.Assert;
import org.junit.Test;

public class CborUtilsTest {
  @Test
  public void testDecodeNullThrows() {
    Assert.assertThrows(CborException.class, () -> CborUtils.decode(null));
  }

  @Test
  public void testEncodeNullThrows() {
    Assert.assertThrows(CborException.class, () -> CborUtils.encode(null));
  }

  @Test
  public void testAsMapNullThrows() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asMap(null));
  }

  @Test
  public void testAsArrayNullThrows() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asArray(null));
  }

  @Test
  public void testAsArrayThreeArgsNullSemanticNameThrows() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asArray(new Array(), 0, null));
  }

  @Test
  public void testAsArrayThreeArgsNullDataItemThrows() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asArray(null, 0, "name"));
  }

  @Test
  public void testAsByteStringNullThrows() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asByteString(null));
  }

  @Test
  public void testAsUnicodeStringNullThrows() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asUnicodeString(null));
  }

  @Test
  public void testAsIntegerNullThrows() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asInteger(null));
  }

  @Test
  public void testIsNullReturnsFalseForNull() {
    Assert.assertFalse(CborUtils.isNull(null));
  }

  @Test
  public void testEncodeDecode() throws CborException {
    UnicodeString item = new UnicodeString("test");
    byte[] encoded = CborUtils.encode(item);
    DataItem decoded = CborUtils.decode(encoded);
    Assert.assertEquals(item, decoded);
  }

  @Test
  public void testAsMapPositive() throws CborException {
    Map map = new Map();
    Assert.assertEquals(map, CborUtils.asMap(map));
  }

  @Test
  public void testAsMapNegativeWrongType() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asMap(new Array()));
  }

  @Test
  public void testAsArrayPositive() throws CborException {
    Array array = new Array();
    Assert.assertEquals(array, CborUtils.asArray(array));
  }

  @Test
  public void testAsArrayNegativeWrongType() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asArray(new Map()));
  }

  @Test
  public void testAsArrayThreeArgsPositive() throws CborException {
    Array array = new Array();
    array.add(new UnicodeString("item"));
    Assert.assertEquals(array, CborUtils.asArray(array, 1, "test-array"));
  }

  @Test
  public void testAsArrayThreeArgsWrongSizeThrows() {
    Array array = new Array();
    Assert.assertThrows(CborException.class, () -> CborUtils.asArray(array, 1, "test-array"));
  }

  @Test
  public void testAsByteStringPositive() throws CborException {
    ByteString bs = new ByteString(new byte[]{1, 2, 3});
    Assert.assertEquals(bs, CborUtils.asByteString(bs));
    Assert.assertArrayEquals(new byte[]{1, 2, 3}, CborUtils.getBytes(bs));
  }

  @Test
  public void testAsByteStringNegativeWrongType() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asByteString(new UnicodeString("not bytes")));
  }

  @Test
  public void testAsUnicodeStringPositive() throws CborException {
    UnicodeString us = new UnicodeString("hello");
    Assert.assertEquals(us, CborUtils.asUnicodeString(us));
    Assert.assertEquals("hello", CborUtils.getString(us));
  }

  @Test
  public void testAsUnicodeStringNegativeWrongType() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asUnicodeString(new ByteString(new byte[]{1})));
  }

  @Test
  public void testAsIntegerPositive() throws CborException {
    UnsignedInteger ui = new UnsignedInteger(123);
    Assert.assertEquals(123, CborUtils.asInteger(ui));

    NegativeInteger ni = new NegativeInteger(-123);
    Assert.assertEquals(-123, CborUtils.asInteger(ni));
  }

  @Test
  public void testAsIntegerNegativeWrongType() {
    Assert.assertThrows(CborException.class, () -> CborUtils.asInteger(new UnicodeString("not a number")));
  }

  @Test
  public void testIsNullPositive() {
    Assert.assertTrue(CborUtils.isNull(SimpleValue.NULL));
    Assert.assertFalse(CborUtils.isNull(SimpleValue.TRUE));
    Assert.assertFalse(CborUtils.isNull(new UnicodeString("not null")));
  }
}
