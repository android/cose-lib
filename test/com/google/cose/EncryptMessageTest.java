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
public class EncryptMessageTest {
  @Test
  public void testDeserialize() throws CborException, CoseException {
    EncryptMessage message = EncryptMessage.deserialize(TestUtilities.hexStringToByteArray(
      "8443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C"
          + "80039826350B97AE2300E42FD818340A20125044A6F75722D73656372657440"
    ));
    Assert.assertEquals("60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FD",
        TestUtilities.bytesToHexString(message.getCiphertext()));
    Assert.assertEquals("A10101",
        TestUtilities.bytesToHexString(CborUtils.encode(message.getProtectedHeaders())));
    Map protectedHeaders = message.getProtectedHeaders();
    Assert.assertEquals(1, protectedHeaders.getKeys().size());
    Assert.assertEquals(Algorithm.ENCRYPTION_AES_128_GCM.getCoseAlgorithmId(),
        protectedHeaders.get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
    Assert.assertEquals(
        new ByteString(TestUtilities.hexStringToByteArray("02D1F7E6F26C43D4868D87CE")),
        message.getUnprotectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_BASE_IV)));
    Assert.assertEquals(1, message.getRecipients().size());

    Recipient r = message.getRecipients().get(0);
    Assert.assertEquals(0, r.getProtectedHeaders().getKeys().size());
    Assert.assertEquals("", TestUtilities.bytesToHexString(r.getCiphertext()));
    Assert.assertEquals(0, r.getRecipients().size());
    Assert.assertEquals(0, r.getProtectedHeaders().getKeys().size());

    Map headers = r.getUnprotectedHeaders();
    Assert.assertEquals(new ByteString(TestUtilities.SHARED_KEY_ID_BYTES),
        headers.get(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID)));
    Assert.assertEquals(Algorithm.DIRECT_CEK_USAGE.getCoseAlgorithmId(),
        headers.get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
  }

  @Test
  public void testSerializeWithProtectedHeaders() throws CborException, CoseException {
    Map protectedHeaders = new Map();
    protectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.ENCRYPTION_AES_128_GCM.getCoseAlgorithmId());
    Map unprotectedMessageHeaders = new Map();
    unprotectedMessageHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_BASE_IV),
        new ByteString(TestUtilities.hexStringToByteArray("02D1F7E6F26C43D4868D87CE")));

    Map unprotectedRecipientHeaders = new Map();
    unprotectedRecipientHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.DIRECT_CEK_USAGE.getCoseAlgorithmId());
    unprotectedRecipientHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID),
        new ByteString(TestUtilities.SHARED_KEY_ID_BYTES));
    Recipient r = Recipient.builder()
        .withProtectedHeaders(new Map())
        .withUnprotectedHeaders(unprotectedRecipientHeaders)
        .withCiphertext(new byte[0])
        .build();

    Assert.assertEquals("8340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(r.serialize()));

    EncryptMessage message = EncryptMessage.builder()
        .withProtectedHeaders(protectedHeaders)
        .withUnprotectedHeaders(unprotectedMessageHeaders)
        .withCiphertext(TestUtilities.hexStringToByteArray(
            "60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FD"))
        .withRecipients(r)
        .build();

    Assert.assertEquals("8443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1"
            + "DD25867374B3581F2C80039826350B97AE2300E42FD818340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(message.serialize()));
  }

  @Test
  public void testParsingNullCiphertext() throws CborException, CoseException {
    String cborString = "8443A10101A1054C02D1F7E6F26C43D4868D87CEF6818340A20125044A6F75722D7365637"
        + "2657440";
    EncryptMessage e = EncryptMessage.deserialize(TestUtilities.hexStringToByteArray(cborString));
    Assert.assertNull(e.getCiphertext());
  }

  @Test
  public void testEmptyBuilderFailure() {
    try {
      EncryptMessage.builder().build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }

  @Test
  public void testMissingOptionBuilderFailure() {
    try {
      EncryptMessage.builder().withProtectedHeaders(new Map()).build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }

  @Test
  public void testEmptyRecipientsBuilderFailure() {
    try {
      EncryptMessage.builder()
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
  public void testDecodeFailureWithEmptyRecipients() throws CborException {
    String cborString = "8443A10101A1054C02D1F7E6F26C43D4868D87CEF680";
    try {
      EncryptMessage.deserialize(TestUtilities.hexStringToByteArray(cborString));
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
      EncryptMessage.deserialize(TestUtilities.hexStringToByteArray(cborString));
      Assert.fail();
    } catch (CborException e) {
      // pass
    }
  }
}
