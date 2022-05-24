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
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Headers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test class for testing {@link MacKey}
 */
@RunWith(JUnit4.class)
public class MacKeyTest {
  @Test
  public void testRoundTrip() throws CborException, CoseException {
    final String kVal = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
    final byte[] k = TestUtilities.hexStringToByteArray(kVal);
    final String keyId = "meriadoc.brandybuck@buckland.example";
    final Map map = new Map();
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_TYPE),
        new UnsignedInteger(Headers.KEY_TYPE_SYMMETRIC));
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_ID), new ByteString(keyId.getBytes()));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_K), new ByteString(k));

    final MacKey key = MacKey.decode(map);
    byte[] a = key.serialize();

    final MacKey newKey = MacKey.parse(a);

    Assert.assertEquals(Headers.KEY_TYPE_SYMMETRIC, newKey.getKeyType());
    Assert.assertEquals(keyId, newKey.getKeyId());
    Assert.assertEquals(new ByteString(k), newKey.getLabels().get(Headers.KEY_PARAMETER_K));

    byte[] b = newKey.serialize();
    Assert.assertEquals(a.length, b.length);
    for (int i = 0; i < a.length; i++) {
      Assert.assertEquals(a[i], b[i]);
    }
  }

  @Test
  public void testConversion() throws CborException, CoseException {
    final String cborString = "A301040258246D65726961646F632E6272616E64796275636B406275636B6C616E6"
        + "42E6578616D706C6520582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D";
    final String kVal = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
    final ByteString k = new ByteString(TestUtilities.hexStringToByteArray(kVal));
    final MacKey mKey = MacKey.parse(TestUtilities.hexStringToByteArray(cborString));
    Assert.assertEquals(Headers.KEY_TYPE_SYMMETRIC, mKey.getKeyType());
    Assert.assertEquals(k, mKey.getLabels().get(Headers.KEY_PARAMETER_K));
  }

  @Test
  public void testBuilder() throws CborException, CoseException {
    final String cborString = "A301040258246D65726961646F632E6272616E64796275636B406275636B6C616E6"
        + "42E6578616D706C6520582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D";
    final String kVal = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
    MacKey macKey = MacKey.builder()
        .withSecretKey(TestUtilities.hexStringToByteArray(kVal))
        .withKeyId("meriadoc.brandybuck@buckland.example")
        .build();
    Assert.assertEquals(cborString, TestUtilities.bytesToHexString(macKey.serialize()));
  }

  @Test
  public void testBuilderFailureScenarios() throws CborException {
    final String kVal = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
    final byte[] secretKey = TestUtilities.hexStringToByteArray(kVal);
    try {
      MacKey.builder().build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }

    try {
      MacKey.builder()
          .withSecretKey(secretKey)
          .withOperations(Headers.KEY_OPERATIONS_SIGN, Headers.KEY_OPERATIONS_MAC_CREATE)
          .build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }

    try {
      MacKey.builder()
          .withSecretKey(new byte[0])
          .build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }

  @Test(expected = CoseException.class)
  public void testEmptySecretByteArray() throws CborException, CoseException {
    String cborString = "A301040258246D65726961646F632E6272616E64796275636B406275636B6C616E642E657"
        + "8616D706C652040";
    MacKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }
}
