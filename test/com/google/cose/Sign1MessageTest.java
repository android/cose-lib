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
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.Headers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class Sign1MessageTest {
  @Test
  public void testDeserialize() throws CborException, CoseException {
    Sign1Message message =
        Sign1Message.deserialize(
            TestUtilities.hexStringToByteArray(
                "8441A0A20126044"
                    + "2313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4"
                    + "D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F"));
    Assert.assertArrayEquals(TestUtilities.CONTENT_BYTES, message.getMessage());
    Assert.assertEquals("87DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127"
            + "FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F",
        TestUtilities.bytesToHexString(message.getSignature()));
    Assert.assertEquals(0, message.getProtectedHeaders().getKeys().size());

    Map headers = message.getUnprotectedHeaders();
    Assert.assertEquals(2, headers.getKeys().size());
    Assert.assertEquals(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256.getCoseAlgorithmId(),
        headers.get(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM)));
    Assert.assertEquals(new ByteString(TestUtilities.hexStringToByteArray("3131")),
        headers.get(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID)));
  }

  @Test
  public void testSerializeWithProtectedHeaders() throws CborException, CoseException {
    Map map = new Map();
    map.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256.getCoseAlgorithmId());
    map.put(new UnsignedInteger(Headers.MESSAGE_HEADER_KEY_ID),
        new ByteString(TestUtilities.hexStringToByteArray("3131")));

    Sign1Message message = Sign1Message.builder()
        .withProtectedHeaders(new Map())
        .withUnprotectedHeaders(map)
        .withMessage(TestUtilities.CONTENT_BYTES)
        .withSignature(TestUtilities.hexStringToByteArray("87DB0D2E5571843B78AC33ECB2830DF7B6E0A4D"
            + "5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D"
            + "27244F"))
        .build();
    Assert.assertEquals("8440A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2"
      + "E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B2"
      + "33BF722B64072BEB4486BDA4031D27244F", TestUtilities.bytesToHexString(message.serialize()));
  }

  @Test
  public void testParsingNullMessage() throws CborException, CoseException {
    String cborString = "8440A2012604423131F6584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE33"
        + "6B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F";
    Sign1Message e = Sign1Message.deserialize(TestUtilities.hexStringToByteArray(cborString));
    Assert.assertNull(e.getMessage());
  }

  @Test
  public void testEmptyBuilderFailure() {
    assertThrows(CoseException.class, () -> Sign1Message.builder().build());
  }

  @Test
  public void testMissingOptionBuilderFailure() {
    assertThrows(
        CoseException.class, () -> Sign1Message.builder().withProtectedHeaders(new Map()).build());
  }

  @Test
  public void testByteParsingFailure() throws CoseException {
    String cborString = "A301040258246D65726961646F632E6272616E64796275636B406275636B6C616E642E657"
        + "8616D706C652040";
    assertThrows(
        CborException.class,
        () -> Sign1Message.deserialize(TestUtilities.hexStringToByteArray(cborString)));
  }
}
