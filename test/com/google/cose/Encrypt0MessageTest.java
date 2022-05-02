package com.google.cose;

import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.utils.CborUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class Encrypt0MessageTest {
  @Test
  public void testDeserialize() {
    Encrypt0Message message = Encrypt0Message.deserialize(TestUtilities.hexStringToByteArray(
      "8343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C0"
          + "3568B41F57C3CC16F9166250B"
    ));
    Assert.assertEquals("60973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250B",
        TestUtilities.bytesToHexString(message.getCiphertext()));
    Assert.assertEquals("A10101",
        TestUtilities.bytesToHexString(message.getProtectedHeaderBytes()));
    Assert.assertEquals(message.getUnprotectedHeaders().get(new UnsignedInteger(5)),
        new ByteString(TestUtilities.hexStringToByteArray("02D1F7E6F26C43D4868D87CE")));
  }

  @Test
  public void testSerialize() {
    DataItem protectedHeaders = new Map();
    Map map = new Map();
    map.put(new UnsignedInteger(1), new UnsignedInteger(1));
    map.put(new UnsignedInteger(5), new ByteString(TestUtilities.hexStringToByteArray(
        "02D1F7E6F26C43D4868D87CE")));
    Encrypt0Message message = Encrypt0Message.builder()
        .withProtectedHeaderBytes(CborUtils.encode(protectedHeaders))
        .withUnprotectedHeaders(map)
        .withCiphertext(TestUtilities.hexStringToByteArray(
            "60973A94BB2898009EE52ECFD9AB1DD25867374B24BEE54AA5D797C8DC845929ACAA47EF"))
        .build();
    Assert.assertEquals("8341A0A20101054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1"
        + "DD25867374B24BEE54AA5D797C8DC845929ACAA47EF",
        TestUtilities.bytesToHexString(message.serialize()));
  }
}
