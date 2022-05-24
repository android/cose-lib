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

package com.google.cose;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SignMessageTest {
  @Test
  public void testDeserialize() throws CoseException, CborException {
    SignMessage message = SignMessage.deserialize(TestUtilities.hexStringToByteArray(
      "8441A0A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19"
          + "DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D3"
          + "4816FE926A2B98F53AFD2FA0F30A"));
    Assert.assertEquals(TestUtilities.CONTENT, new String(message.getMessage()));
    Assert.assertEquals(0, message.getProtectedHeaders().getKeys().size());
    Assert.assertEquals(0, message.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals(1, message.getSignatures().size());

    Signature s = message.getSignatures().get(0);
    Map headers = s.getProtectedHeaders();
    Assert.assertEquals(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256.getCoseAlgorithmId(),
        headers.get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));

    Assert.assertEquals("A10126",
        TestUtilities.bytesToHexString(CborUtils.encode(s.getProtectedHeaders())));
    Assert.assertEquals(1, s.getProtectedHeaders().getKeys().size());
    Assert.assertEquals(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256.getCoseAlgorithmId(),
        s.getProtectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
    Assert.assertEquals(1, s.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals(new ByteString(TestUtilities.hexStringToByteArray("3131")),
        s.getUnprotectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID)));
    Assert.assertEquals("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B"
        + "8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        TestUtilities.bytesToHexString(s.getSignature()));
  }

  @Test
  public void testDeserializeWithEmptyProtectedHeaders() throws CoseException, CborException {
    SignMessage message = SignMessage.deserialize(TestUtilities.hexStringToByteArray(
      "8440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19"
          + "DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D3"
          + "4816FE926A2B98F53AFD2FA0F30A"));
    Assert.assertEquals(TestUtilities.CONTENT, new String(message.getMessage()));
    Assert.assertEquals(0, message.getProtectedHeaders().getKeys().size());
    Assert.assertEquals(0, message.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals(1, message.getSignatures().size());

    Signature s = message.getSignatures().get(0);
    Assert.assertEquals(1, s.getProtectedHeaders().getKeys().size());
    Assert.assertEquals(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256.getCoseAlgorithmId(),
        s.getProtectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
    Assert.assertEquals(1, s.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals("A10126",
        TestUtilities.bytesToHexString(CborUtils.encode(s.getProtectedHeaders())));
    Assert.assertEquals(new ByteString(TestUtilities.hexStringToByteArray("3131")),
        s.getUnprotectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID)));
    Assert.assertEquals("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B"
            + "8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        TestUtilities.bytesToHexString(s.getSignature()));
  }

  @Test
  public void testSerializeWithProtectedHeaders() throws CoseException, CborException {
    Map protectedHeaders = new Map();
    protectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256.getCoseAlgorithmId());

    Map unprotectedHeaders = new Map();
    unprotectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID),
        new ByteString(TestUtilities.hexStringToByteArray("3131")));

    Signature s = Signature.builder()
        .withProtectedHeaders(protectedHeaders)
        .withUnprotectedHeaders(unprotectedHeaders)
        .withSignature(TestUtilities.hexStringToByteArray("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282"
            + "CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2F"
            + "A0F30A"))
        .build();

    SignMessage message = SignMessage.builder()
        .withProtectedHeaders(new Map())
        .withUnprotectedHeaders(new Map())
        .withMessage(TestUtilities.CONTENT.getBytes())
        .withSignatures(s)
        .build();

    Assert.assertEquals("8440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315"
        + "840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B45"
        + "07DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        TestUtilities.bytesToHexString(message.serialize()));
  }

  @Test(expected = CoseException.class)
  public void testBuilderAllFieldsMissing() throws CoseException {
    SignMessage.builder().build();
    Assert.fail();
  }

  @Test(expected = CoseException.class)
  public void testBuilderSignatureMissing() throws CoseException {
    SignMessage.builder()
        .withMessage(TestUtilities.CONTENT.getBytes())
        .withProtectedHeaders(new Map())
        .withUnprotectedHeaders(new Map())
        .withSignatures()
        .build();
    Assert.fail();
  }

  @Test
  public void testParsingNullMessage() throws CborException, CoseException {
    String cborString = "8440A0F6818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282"
      + "CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A";
    SignMessage e = SignMessage.deserialize(TestUtilities.hexStringToByteArray(cborString));
    Assert.assertNull(e.getMessage());
  }

  @Test
  public void testBuilderFailures() {
    try {
      Encrypt0Message.builder().build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }

    try {
      Encrypt0Message.builder().withProtectedHeaders(new Map()).build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }

  @Test(expected = CborException.class)
  public void testByteParsingFailure() throws CborException, CoseException {
    String cborString = "A301040258246D65726961646F632E6272616E64796275636B406275636B6C616E642E657"
        + "8616D706C652040";
    SignMessage.deserialize(TestUtilities.hexStringToByteArray(cborString));
  }

  @Test(expected = CoseException.class)
  public void testDecodeFailureWithEmptySignatures() throws CborException, CoseException {
    String cborString = "8440A0F680";
    SignMessage.deserialize(TestUtilities.hexStringToByteArray(cborString));
  }
}
