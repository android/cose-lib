package com.google.cose;

import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.utils.CborUtils;
import java.util.Collections;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SignMessageTest {
  @Test
  public void testDeserialize() {
    SignMessage message = SignMessage.deserialize(TestUtilities.hexStringToByteArray(
      "8441A0A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19"
          + "DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D3"
          + "4816FE926A2B98F53AFD2FA0F30A"));
    Assert.assertEquals(TestUtilities.CONTENT, new String(message.getMessage()));
    Assert.assertEquals("A0", TestUtilities.bytesToHexString(message.getProtectedHeaderBytes()));
    Assert.assertEquals(0, message.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals(1, message.getSignatures().size());

    Signature s = message.getSignatures().get(0);
    Assert.assertEquals("A10126", TestUtilities.bytesToHexString(s.getProtectedHeaderBytes()));
    Assert.assertEquals(1, s.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals(new ByteString(TestUtilities.hexStringToByteArray("3131")),
        s.getUnprotectedHeaders().get(new UnsignedInteger(4)));
    Assert.assertEquals("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B"
        + "8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        TestUtilities.bytesToHexString(s.getSignature()));
  }

  @Test
  public void testDeserialize2() {
    SignMessage message = SignMessage.deserialize(TestUtilities.hexStringToByteArray(
      "8440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19"
          + "DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D3"
          + "4816FE926A2B98F53AFD2FA0F30A"));
    Assert.assertEquals(TestUtilities.CONTENT, new String(message.getMessage()));
    Assert.assertEquals("", TestUtilities.bytesToHexString(message.getProtectedHeaderBytes()));
    Assert.assertEquals(0, message.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals(1, message.getSignatures().size());

    Signature s = message.getSignatures().get(0);
    Assert.assertEquals(1, s.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals("A10126", TestUtilities.bytesToHexString(s.getProtectedHeaderBytes()));
    Assert.assertEquals(new ByteString(TestUtilities.hexStringToByteArray("3131")),
        s.getUnprotectedHeaders().get(new UnsignedInteger(4)));
    Assert.assertEquals("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B"
            + "8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        TestUtilities.bytesToHexString(s.getSignature()));
  }

  @Test
  public void testSerialize() {
    Map unprotectedHeaders = new Map();
    unprotectedHeaders.put(new UnsignedInteger(4),
        new ByteString(TestUtilities.hexStringToByteArray("3131")));

    Signature s = Signature.builder()
        .withProtectedHeaderBytes(TestUtilities.hexStringToByteArray("A10126"))
        .withUnprotectedHeaders(unprotectedHeaders)
        .withSignature(TestUtilities.hexStringToByteArray("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282"
            + "CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2F"
            + "A0F30A"))
        .build();

    SignMessage message = SignMessage.builder()
        .withProtectedHeaderBytes(CborUtils.encode(new Map()))
        .withUnprotectedHeaders(new Map())
        .withMessage(TestUtilities.CONTENT.getBytes())
        .withSignatures(Collections.singletonList(s))
        .build();

    Assert.assertEquals("8441A0A054546869732069732074686520636F6E74656E742E818343A10126A1044231315"
        + "840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B45"
        + "07DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        TestUtilities.bytesToHexString(message.serialize()));
  }
}
