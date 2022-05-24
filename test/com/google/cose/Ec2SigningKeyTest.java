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
 * Test class for testing {@link Ec2SigningKey}
 */
@RunWith(JUnit4.class)
public class Ec2SigningKeyTest {
  @Test
  public void testRoundTrip() throws CborException, CoseException {
    final String xVal = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
    final byte[] x = TestUtilities.hexStringToByteArray(xVal);
    final String yVal = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";
    final byte[] y = TestUtilities.hexStringToByteArray(yVal);
    final String keyId = "meriadoc.brandybuck@buckland.example";
    final Map map = new Map();
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_TYPE),
        new UnsignedInteger(Headers.KEY_TYPE_EC2));
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_ID), new ByteString(keyId.getBytes()));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_CURVE),
        new UnsignedInteger(Headers.CURVE_EC2_P256));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_X), new ByteString(x));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_Y), new ByteString(y));

    final Ec2SigningKey key = new Ec2SigningKey(map);
    byte[] a = key.serialize();

    final Ec2SigningKey newKey = Ec2SigningKey.parse(a);

    Assert.assertEquals(Headers.KEY_TYPE_EC2, newKey.getKeyType());
    Assert.assertEquals(keyId, newKey.getKeyId());
    Assert.assertEquals(new UnsignedInteger(Headers.CURVE_EC2_P256),
        newKey.getLabels().get(Headers.KEY_PARAMETER_CURVE));
    Assert.assertEquals(new ByteString(x), newKey.getLabels().get(Headers.KEY_PARAMETER_X));
    Assert.assertEquals(new ByteString(y), newKey.getLabels().get(Headers.KEY_PARAMETER_Y));

    byte[] b = newKey.serialize();
    Assert.assertEquals(a.length, b.length);
    for (int i = 0; i < a.length; i++) {
      Assert.assertEquals(a[i], b[i]);
    }
  }

  @Test
  public void testConversion() throws CborException, CoseException {
    final String cborString = "A4010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
        + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    final String xVal = "5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE";
    final ByteString x = new ByteString(TestUtilities.hexStringToByteArray(xVal));
    final String yVal = "B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    final ByteString y = new ByteString(TestUtilities.hexStringToByteArray(yVal));
    final Ec2SigningKey sKey = Ec2SigningKey.parse(TestUtilities.hexStringToByteArray(cborString));
    Assert.assertEquals(Headers.KEY_TYPE_EC2, sKey.getKeyType());
    Assert.assertEquals(new UnsignedInteger(Headers.CURVE_EC2_P256),
        sKey.getLabels().get(Headers.KEY_PARAMETER_CURVE));
    Assert.assertEquals(x, sKey.getLabels().get(Headers.KEY_PARAMETER_X));
    Assert.assertEquals(y, sKey.getLabels().get(Headers.KEY_PARAMETER_Y));
  }

  @Test
  public void testBuilder() throws CborException, CoseException {
    final String cborString = "A4010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
        + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    final String x = "5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE";
    final String y = "B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    Ec2SigningKey signingKey = Ec2SigningKey.builder()
        .withCurve(Headers.CURVE_EC2_P256)
        .withXCoordinate(TestUtilities.hexStringToByteArray(x))
        .withYCoordinate(TestUtilities.hexStringToByteArray(y))
        .build();
    Assert.assertEquals(cborString, TestUtilities.bytesToHexString(signingKey.serialize()));
  }

  @Test
  public void testBuilderPrivateKey() throws CborException, CoseException {
    final String cborString = "A3010220012358205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
        + "4B624343167FE";
    final String d = "5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE";
    Ec2SigningKey signingKey = Ec2SigningKey.builder()
        .withCurve(Headers.CURVE_EC2_P256)
        .withDParameter(TestUtilities.hexStringToByteArray(d))
        .build();
    Assert.assertEquals(cborString, TestUtilities.bytesToHexString(signingKey.serialize()));
  }

  @Test
  public void testBuilderFailureScenarios() throws CborException, CoseException {
    final String xCor = "5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE";
    final String yCor = "B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    final String dParam = "5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE";
    final byte[] x = TestUtilities.hexStringToByteArray(xCor);
    final byte[] y = TestUtilities.hexStringToByteArray(yCor);
    final byte[] d = TestUtilities.hexStringToByteArray(dParam);

    try {
      Ec2SigningKey.builder().build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }

    // Missing curve
    try {
      Ec2SigningKey.builder()
          .withXCoordinate(x)
          .withYCoordinate(y)
          .withDParameter(d)
          .build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }

    // Incorrect curve
    try {
      Ec2SigningKey.builder()
          .withCurve(Headers.CURVE_OKP_Ed25519)
          .withXCoordinate(x)
          .withYCoordinate(y)
          .withDParameter(d)
          .build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }

    // Missing x
    try {
      Ec2SigningKey.builder()
          .withCurve(Headers.CURVE_EC2_P256)
          .withYCoordinate(y)
          .withDParameter(d)
          .build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }

    // Missing y
    try {
      Ec2SigningKey.builder()
          .withCurve(Headers.CURVE_EC2_P256)
          .withXCoordinate(x)
          .withDParameter(d)
          .build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }

    // Missing d should pass
    Ec2SigningKey.builder()
        .withCurve(Headers.CURVE_EC2_P256)
        .withXCoordinate(x)
        .withYCoordinate(y)
        .build();

    // Wrong operation
    try {
      Ec2SigningKey.builder()
          .withCurve(Headers.CURVE_EC2_P256)
          .withXCoordinate(x)
          .withYCoordinate(y)
          .withDParameter(d)
          .withOperations(Headers.KEY_OPERATIONS_DECRYPT, Headers.KEY_OPERATIONS_SIGN)
          .build();
      Assert.fail();
    } catch (CoseException e) {
      // pass
    }
  }

  @Test(expected = CoseException.class)
  public void testOkpKeyParsingInEc2SigningKey() throws CborException, CoseException {
    String cborString = "A401012006215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F"
        + "707511A2358209D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    Ec2SigningKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }

  @Test(expected = CoseException.class)
  public void testEc2KeyParsingWithIncorrectCurve() throws CborException, CoseException {
    String cborString = "A401022006215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F"
        + "707511A2358209D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    Ec2SigningKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }

  @Test(expected = CoseException.class)
  public void testNullDParameterBytes() throws CborException, CoseException {
    String cborString = "A5010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B6243"
        + "43167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC672340";
    Ec2SigningKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }
}
