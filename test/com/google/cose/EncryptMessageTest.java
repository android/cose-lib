package com.google.cose;

import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.utils.CborUtils;
import java.util.Collections;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class EncryptMessageTest {
  @Test
  public void testDeserialize() {
    EncryptMessage message = EncryptMessage.deserialize(TestUtilities.hexStringToByteArray(
      "8443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C"
          + "80039826350B97AE2300E42FD818340A20125044A6F75722D73656372657440"
    ));
    Assert.assertEquals("60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FD",
        TestUtilities.bytesToHexString(message.getCiphertext()));
    Assert.assertEquals("A10101",
        TestUtilities.bytesToHexString(message.getProtectedHeaderBytes()));
    Assert.assertEquals(
        new ByteString(TestUtilities.hexStringToByteArray("02D1F7E6F26C43D4868D87CE")),
        message.getUnprotectedHeaders().get(new UnsignedInteger(5)));
    Assert.assertEquals(1, message.getRecipients().size());

    Recipient r = message.getRecipients().get(0);
    Assert.assertEquals("", TestUtilities.bytesToHexString(r.getProtectedHeaderBytes()));
    Assert.assertEquals("", TestUtilities.bytesToHexString(r.getCiphertext()));

    Map headers = r.getUnprotectedHeaders();
    Assert.assertEquals(new ByteString(TestUtilities.hexStringToByteArray("6F75722D736563726574")),
        headers.get(new UnsignedInteger(4)));
    Assert.assertEquals(new NegativeInteger(-6), headers.get(new UnsignedInteger(1)));
  }

  @Test
  public void testSerialize() {
    Map protectedHeaders = new Map();
    protectedHeaders.put(new UnsignedInteger(1), new UnsignedInteger(1));
    Map unprotectedHeaders = new Map();
    unprotectedHeaders.put(new UnsignedInteger(5),
        new ByteString(TestUtilities.hexStringToByteArray("02D1F7E6F26C43D4868D87CE")));
    EncryptMessage.Builder message = EncryptMessage.builder()
        .withProtectedHeaderBytes(CborUtils.encode(protectedHeaders))
        .withUnprotectedHeaders(unprotectedHeaders)
        .withCiphertext(TestUtilities.hexStringToByteArray(
            "60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FD"));

    unprotectedHeaders = new Map();
    unprotectedHeaders.put(new UnsignedInteger(1), new NegativeInteger(-6));
    unprotectedHeaders.put(
        new UnsignedInteger(4),
        new ByteString(TestUtilities.hexStringToByteArray("6F75722D736563726574")));
    Recipient r = Recipient.builder()
        .withProtectedHeaderBytes(new byte[0])
        .withUnprotectedHeaders(unprotectedHeaders)
        .withCiphertext(new byte[0])
        .build();

    Assert.assertEquals("8340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(r.serialize()));
    message.withRecipients(Collections.singletonList(r));

    Assert.assertEquals("8443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1"
            + "DD25867374B3581F2C80039826350B97AE2300E42FD818340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(message.build().serialize()));
  }
}
