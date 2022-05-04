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
public class EncryptMessageTest {
  @Test
  public void testDeserialize() throws CoseException, CborException {
    EncryptMessage message = EncryptMessage.deserialize(TestUtilities.hexStringToByteArray(
      "8443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C"
          + "80039826350B97AE2300E42FD818340A20125044A6F75722D73656372657440"
    ));
    Assert.assertEquals("60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FD",
        TestUtilities.bytesToHexString(message.getCiphertext()));
    Assert.assertEquals("A10101",
        TestUtilities.bytesToHexString(message.getProtectedHeaderBytes()));
    Map protectedHeaders = message.getProtectedHeaders();
    Assert.assertEquals(1, protectedHeaders.getKeys().size());
    Assert.assertEquals(Algorithm.ENCRYPTION_AES_128_GCM.getCoseAlgorithmId(),
        protectedHeaders.get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
    Assert.assertEquals(
        new ByteString(TestUtilities.hexStringToByteArray("02D1F7E6F26C43D4868D87CE")),
        message.getUnprotectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_BASE_IV)));
    Assert.assertEquals(1, message.getRecipients().size());

    Recipient r = message.getRecipients().get(0);
    Assert.assertEquals("", TestUtilities.bytesToHexString(r.getProtectedHeaderBytes()));
    Assert.assertEquals("", TestUtilities.bytesToHexString(r.getCiphertext()));
    Assert.assertEquals(0, r.getRecipients().size());
    Assert.assertEquals(0, r.getProtectedHeaders().getKeys().size());

    Map headers = r.getUnprotectedHeaders();
    Assert.assertEquals(new ByteString(TestUtilities.SHARED_KEY_ID.getBytes()),
        headers.get(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID)));
    Assert.assertEquals(Algorithm.DIRECT_CEK_USAGE.getCoseAlgorithmId(),
        headers.get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
  }

  @Test
  public void testSerializeWithProtectedHeaderBytes() throws CborException, CoseException {
    Map protectedHeaders = new Map();
    protectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.ENCRYPTION_AES_128_GCM.getCoseAlgorithmId());
    Map unprotectedHeaders = new Map();
    unprotectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_BASE_IV),
        new ByteString(TestUtilities.hexStringToByteArray("02D1F7E6F26C43D4868D87CE")));
    EncryptMessage.Builder message = EncryptMessage.builder()
        .withProtectedHeaderBytes(CborUtils.encode(protectedHeaders))
        .withUnprotectedHeaders(unprotectedHeaders)
        .withCiphertext(TestUtilities.hexStringToByteArray(
            "60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FD"));

    unprotectedHeaders = new Map();
    unprotectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.DIRECT_CEK_USAGE.getCoseAlgorithmId());
    unprotectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID),
        new ByteString(TestUtilities.SHARED_KEY_ID.getBytes()));
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
        new ByteString(TestUtilities.SHARED_KEY_ID.getBytes()));
    Recipient r = Recipient.builder()
        .withProtectedHeaders(new Map())
        .withUnprotectedHeaders(unprotectedRecipientHeaders)
        .withCiphertext(new byte[0])
        .build();

    Assert.assertEquals("8340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(r.serialize()));

    EncryptMessage message = EncryptMessage.builder()
        .withProtectedHeaderBytes(CborUtils.encode(protectedHeaders))
        .withUnprotectedHeaders(unprotectedMessageHeaders)
        .withCiphertext(TestUtilities.hexStringToByteArray(
            "60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FD"))
        .withRecipients(r)
        .build();

    Assert.assertEquals("8443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1"
            + "DD25867374B3581F2C80039826350B97AE2300E42FD818340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(message.serialize()));
  }
}
