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
import co.nstant.in.cbor.model.DataItem;
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
public class Encrypt0MessageTest {
  @Test
  public void testDeserialize() throws CoseException, CborException {
    Encrypt0Message message = Encrypt0Message.deserialize(TestUtilities.hexStringToByteArray(
      "8343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C0"
          + "3568B41F57C3CC16F9166250B"
    ));
    Assert.assertEquals("60973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250B",
        TestUtilities.bytesToHexString(message.getCiphertext()));
    Assert.assertEquals("A10101",
        TestUtilities.bytesToHexString(message.getProtectedHeaderBytes()));
    Assert.assertEquals(
        message.getUnprotectedHeaders().get(new UnsignedInteger(Headers.MESSAGE_HEADER_BASE_IV)),
        new ByteString(TestUtilities.hexStringToByteArray("02D1F7E6F26C43D4868D87CE")));
  }

  @Test
  public void testSerialize() throws CoseException, CborException {
    DataItem protectedHeaders = new Map();
    Map map = new Map();
    map.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.ENCRYPTION_AES_128_GCM.getCoseAlgorithmId());
    map.put(new UnsignedInteger(Headers.MESSAGE_HEADER_BASE_IV),
        new ByteString(TestUtilities.hexStringToByteArray("02D1F7E6F26C43D4868D87CE")));
    Encrypt0Message message = Encrypt0Message.builder()
        .withProtectedHeaderBytes(CborUtils.encode(protectedHeaders))
        .withUnprotectedHeaders(map)
        .withCiphertext(TestUtilities.hexStringToByteArray(
            "60973A94BB2898009EE52ECFD9AB1DD25867374B24BEE54AA5D797C8DC845929ACAA47EF"))
        .build();
    Assert.assertEquals("8341A0A20101054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1"
        + "DD25867374B24BEE54AA5D797C8DC845929ACAA47EF",
        TestUtilities.bytesToHexString(message.serialize()));
  }
}
