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
 * Test class for testing {@link OkpSigningKey}. Key values used in test cases are referenced from
 * https://datatracker.ietf.org/doc/html/rfc8152#appendix-C
 */
@RunWith(JUnit4.class)
public class OkpSigningKeyTest {
  @Test
  public void testRoundTrip() throws CborException, CoseException {
    final String xVal = "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A";
    final byte[] x = TestUtilities.hexStringToByteArray(xVal);
    final String dVal = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    final byte[] d = TestUtilities.hexStringToByteArray(dVal);
    final String keyId = "11";
    final Map map = new Map();
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_TYPE),
        new UnsignedInteger(Headers.KEY_TYPE_OKP));
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_ID), new ByteString(keyId.getBytes()));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_CURVE),
        new UnsignedInteger(Headers.CURVE_OKP_Ed25519));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_X), new ByteString(x));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_D), new ByteString(d));

    final OkpSigningKey key = new OkpSigningKey(map);
    byte[] a = key.serialize();

    final OkpSigningKey newKey = OkpSigningKey.parse(a);

    Assert.assertEquals(Headers.KEY_TYPE_OKP, newKey.getKeyType());
    Assert.assertEquals(keyId, newKey.getKeyId());
    Assert.assertEquals(new UnsignedInteger(Headers.CURVE_OKP_Ed25519),
        newKey.getLabels().get(Headers.KEY_PARAMETER_CURVE));
    Assert.assertEquals(new ByteString(x), newKey.getLabels().get(Headers.KEY_PARAMETER_X));
    Assert.assertEquals(new ByteString(d), newKey.getLabels().get(Headers.KEY_PARAMETER_D));

    byte[] b = newKey.serialize();
    Assert.assertEquals(a.length, b.length);
    for (int i = 0; i < a.length; i++) {
      Assert.assertEquals(a[i], b[i]);
    }
  }

  @Test
  public void testConversion() throws CborException, CoseException {
    final String cborString = "A401012006215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF0"
        + "21A68F707511A2358209D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    final String xVal = "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A";
    final ByteString x = new ByteString(TestUtilities.hexStringToByteArray(xVal));
    final String dVal = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    final ByteString d = new ByteString(TestUtilities.hexStringToByteArray(dVal));
    final OkpSigningKey sKey = OkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString));
    Assert.assertEquals(Headers.KEY_TYPE_OKP, sKey.getKeyType());
    Assert.assertEquals(new UnsignedInteger(Headers.CURVE_OKP_Ed25519),
        sKey.getLabels().get(Headers.KEY_PARAMETER_CURVE));
    Assert.assertEquals(x, sKey.getLabels().get(Headers.KEY_PARAMETER_X));
    Assert.assertEquals(d, sKey.getLabels().get(Headers.KEY_PARAMETER_D));
  }

  @Test
  public void testBuilder() throws CborException, CoseException {
    final String cborString = "A301012006215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF0"
        + "21A68F707511A";
    final String xVal = "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A";
    OkpSigningKey key = OkpSigningKey.builder()
        .withXCoordinate(TestUtilities.hexStringToByteArray(xVal))
        .build();
    Assert.assertEquals(cborString, TestUtilities.bytesToHexString(key.serialize()));
  }

  @Test
  public void testBuilderPrivateKey() throws CborException, CoseException {
    final String cborString = "A401012006215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF0"
        + "21A68F707511A2358209D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    final String xVal = "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A";
    final String dVal = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    OkpSigningKey key = OkpSigningKey.builder()
        .withXCoordinate(TestUtilities.hexStringToByteArray(xVal))
        .withDParameter(TestUtilities.hexStringToByteArray(dVal))
        .build();
    Assert.assertEquals(cborString, TestUtilities.bytesToHexString(key.serialize()));
  }

  @Test
  public void testBuilderFailureScenarios() throws CborException, CoseException {
    final String xVal = "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A";
    final String dVal = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    final byte[] x = TestUtilities.hexStringToByteArray(xVal);
    final byte[] d = TestUtilities.hexStringToByteArray(dVal);

    try {
      OkpSigningKey.builder().build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }

    // Missing x should pass
    try {
      OkpSigningKey.builder()
          .withDParameter(d)
          .build();
    } catch (CoseException e) {
      Assert.fail();
    }

    // so should missing d
    try {
      OkpSigningKey.builder()
          .withXCoordinate(x)
          .build();
    } catch (CoseException e) {
      Assert.fail();
    }

    // Wrong operation
    try {
      OkpSigningKey.builder()
          .withXCoordinate(x)
          .withDParameter(d)
          .withOperations(Headers.KEY_OPERATIONS_DECRYPT, Headers.KEY_OPERATIONS_SIGN)
          .build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }

  @Test(expected = CoseException.class)
  public void testEc2KeyParsingInOkpSigningKey() throws CborException, CoseException {
    String cborString = "A4010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
        + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    OkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }

  @Test(expected = CoseException.class)
  public void testOkpKeyParsingWithIncorrectCurve() throws CborException, CoseException {
    String cborString = "A401012002215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F"
        + "707511A2358209D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    OkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }

  @Test(expected = CoseException.class)
  public void testEmptyPrivateKeyBytes() throws CborException, CoseException {
    String cborString = "A401012006215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F"
        + "707511A2340";
    OkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }

  @Test(expected = CoseException.class)
  public void testEmptyPublicKeyBytes() throws CborException, CoseException {
    String cborString = "A40101200621402358209D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BA"
        + "C031CAE7F60";
    OkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }
}
