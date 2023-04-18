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

import static org.junit.Assert.assertThrows;

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
  public void testDeserialize() throws CborException, CoseException {
    Mac0Message message = Mac0Message.deserialize(TestUtilities.hexStringToByteArray(
      "8443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C82477"
          + "2F223AD4F935293F1789FC3A08D8C58"
    ));
    Assert.assertArrayEquals(TestUtilities.CONTENT_BYTES, message.getMessage());
    Assert.assertEquals("A10105",
        TestUtilities.bytesToHexString(CborUtils.encode(message.getProtectedHeaders())));
    Assert.assertEquals(1, message.getProtectedHeaders().getKeys().size());
    Assert.assertEquals(Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId(),
        message.getProtectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
    Assert.assertEquals(0, message.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals("A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
        TestUtilities.bytesToHexString(message.getTag()));
  }

  @Test
  public void testSerializeWithProtectedHeaders() throws CborException, CoseException {
    Map map = new Map();
    map.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId());
    Mac0Message message = Mac0Message.builder()
        .withProtectedHeaders(map)
        .withUnprotectedHeaders(new Map())
        .withMessage(TestUtilities.CONTENT_BYTES)
        .withTag(TestUtilities.hexStringToByteArray(
            "A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58"))
        .build();
    Assert.assertEquals("8443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D6"
            + "1EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
        TestUtilities.bytesToHexString(message.serialize()));
  }

  @Test
  public void testParsingNullMessage() throws CborException, CoseException {
    String cborString = "8443A10105A0F65820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC"
        + "3A08D8C58";
    Mac0Message e = Mac0Message.deserialize(TestUtilities.hexStringToByteArray(cborString));
    Assert.assertNull(e.getMessage());
  }

  @Test
  public void testEmptyBuilderFailure() {
    assertThrows(CoseException.class, () -> Mac0Message.builder().build());
  }

  @Test
  public void testMissingOptionBuilderFailure() {
    assertThrows(
        CoseException.class, () -> Mac0Message.builder().withProtectedHeaders(new Map()).build());
  }

  @Test
  public void testDecodeFailureOnMissingArrayItems() throws CborException {
    String cborString = "8343A10105A05820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A"
        + "08D8C58";
    assertThrows(
        CoseException.class,
        () -> Mac0Message.deserialize(TestUtilities.hexStringToByteArray(cborString)));
  }

  @Test
  public void testByteParsingFailure() throws CoseException {
    String cborString = "A301040258246D65726961646F632E6272616E64796275636B406275636B6C616E642E657"
        + "8616D706C652040";
    assertThrows(
        CborException.class,
        () -> Mac0Message.deserialize(TestUtilities.hexStringToByteArray(cborString)));
  }
}
