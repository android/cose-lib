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
public class Mac0MessageTest {
  @Test
  public void testDeserialize() throws CoseException, CborException {
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
  public void testSerializeWithProtectedHeaderBytes() throws CoseException, CborException {
    Map map = new Map();
    map.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId());
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

  @Test
  public void testSerializeWithProtectedHeaders() throws CoseException, CborException {
    Map map = new Map();
    map.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId());
    Mac0Message message = Mac0Message.builder()
        .withProtectedHeaders(map)
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
