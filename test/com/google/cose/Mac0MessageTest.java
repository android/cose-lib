package com.google.cose;

import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class Mac0MessageTest {
  @Test
  public void testDeserialize() {
    Mac0Message message = Mac0Message.deserialize(TestUtilities.hexStringToByteArray(
      "8443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C82477"
          + "2F223AD4F935293F1789FC3A08D8C58"
    ));
    Assert.assertEquals(TestUtilities.CONTENT, new String(message.getMessage()));
    Assert.assertEquals("A10105",
        TestUtilities.bytesToHexString(message.getProtectedHeaderBytes()));
    Assert.assertEquals(0, message.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals("A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
        TestUtilities.bytesToHexString(message.getTag()));
  }

  @Test
  public void testSerialize() {
    Map map = new Map();
    map.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getAlgorithmId());
    Mac0Message message = Mac0Message.builder()
        .withProtectedHeaderBytes(CborUtils.encode(map))
        .withUnprotectedHeaders(new Map())
        .withMessage(TestUtilities.CONTENT.getBytes())
        .withTag(TestUtilities.hexStringToByteArray(
            "A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58"))
        .build();
    Assert.assertEquals("8443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D6"
            + "1EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
        TestUtilities.bytesToHexString(message.serialize()));
  }
}
