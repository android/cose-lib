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
import java.util.Collections;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MacMessageTest {
  @Test
  public void testDeserialize() throws CborException, CoseException {
    MacMessage message = MacMessage.deserialize(TestUtilities.hexStringToByteArray(
      "8543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91"
          + "F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440"
    ));
    Assert.assertArrayEquals(TestUtilities.CONTENT_BYTES, message.getMessage());
    Assert.assertEquals("A10105",
        TestUtilities.bytesToHexString(CborUtils.encode(message.getProtectedHeaders())));
    Assert.assertEquals(Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId(),
        message.getProtectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
    Assert.assertEquals(1, message.getProtectedHeaders().getKeys().size());
    Assert.assertEquals(0, message.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals("2BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6",
        TestUtilities.bytesToHexString(message.getTag()));
    Assert.assertEquals(1, message.recipients.size());

    Recipient r = message.recipients.get(0);
    Assert.assertEquals(0, r.getProtectedHeaders().getKeys().size());
    Assert.assertEquals(Algorithm.DIRECT_CEK_USAGE.getCoseAlgorithmId(),
        r.getUnprotectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
    Assert.assertEquals(new ByteString(TestUtilities.SHARED_KEY_ID_BYTES),
        r.getUnprotectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID)));
    Assert.assertEquals("", TestUtilities.bytesToHexString(r.getCiphertext()));
  }

  @Test
  public void testSerializeWithProtectedHeaderBytes() throws CborException, CoseException {
    Map protectedHeaders = new Map();
    protectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId());

    Map unprotectedHeaders = new Map();
    unprotectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.DIRECT_CEK_USAGE.getCoseAlgorithmId());
    unprotectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID),
        new ByteString(TestUtilities.SHARED_KEY_ID_BYTES));

    Recipient r = Recipient.builder()
        .withCiphertext(new byte[0])
        .withUnprotectedHeaders(unprotectedHeaders)
        .withProtectedHeaders(new Map())
        .build();

    MacMessage message = MacMessage.builder()
        .withProtectedHeaders(protectedHeaders)
        .withUnprotectedHeaders(new Map())
        .withMessage(TestUtilities.CONTENT_BYTES)
        .withTag(TestUtilities.hexStringToByteArray(
            "2BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6"))
        .withRecipients(Collections.singletonList(r))
        .build();

    Assert.assertEquals("8340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(r.serialize()));

    Assert.assertEquals("8543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B"
        + "8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(message.serialize()));
  }

  @Test
  public void testSerializeWithProtectedHeaders() throws CborException, CoseException {
    Map protectedHeaders = new Map();
    protectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId());

    Map unprotectedHeaders = new Map();
    unprotectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.DIRECT_CEK_USAGE.getCoseAlgorithmId());
    unprotectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID),
        new ByteString(TestUtilities.SHARED_KEY_ID_BYTES));

    Recipient r = Recipient.builder()
        .withCiphertext(new byte[0])
        .withUnprotectedHeaders(unprotectedHeaders)
        .withProtectedHeaders(new Map())
        .build();

    MacMessage message = MacMessage.builder()
        .withProtectedHeaders(protectedHeaders)
        .withUnprotectedHeaders(new Map())
        .withMessage(TestUtilities.CONTENT_BYTES)
        .withTag(TestUtilities.hexStringToByteArray(
            "2BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6"))
        .withRecipients(Collections.singletonList(r))
        .build();

    Assert.assertEquals("8340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(r.serialize()));

    Assert.assertEquals("8543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B"
        + "8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(message.serialize()));
  }

  @Test
  public void testParsingNullMessage() throws CborException, CoseException {
    String cborString = "8543A10105A0F658202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9A"
        + "D5A6682F6818340A20125044A6F75722D73656372657440";
    MacMessage e = MacMessage.deserialize(TestUtilities.hexStringToByteArray(cborString));
    Assert.assertNull(e.getMessage());
  }

  @Test
  public void testEmptyBuilderFailure() {
    try {
      MacMessage.builder().build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }

  @Test
  public void testMissingOptionBuilderFailure() {
    try {
      MacMessage.builder().withProtectedHeaders(new Map()).build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }

  @Test
  public void testEmptyRecipientsBuilderFailure() {
    try {
      MacMessage.builder()
          .withProtectedHeaders(new Map())
          .withUnprotectedHeaders(new Map())
          .withRecipients()
          .build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }

  @Test
  public void testByteParsingFailure() throws CoseException {
    String cborString = "A301040258246D65726961646F632E6272616E64796275636B406275636B6C616E642E657"
        + "8616D706C652040";
    try {
      MacMessage.deserialize(TestUtilities.hexStringToByteArray(cborString));
      Assert.fail();
    } catch (CborException e) {
      // pass
    }
  }

  @Test
  public void testDecodeFailureOnMissingArrayItems() throws CborException {
    String cborString = "8443A10105A058202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5"
        + "A6682F6818340A20125044A6F75722D73656372657440";
    try {
      MacMessage.deserialize(TestUtilities.hexStringToByteArray(cborString));
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }
}
