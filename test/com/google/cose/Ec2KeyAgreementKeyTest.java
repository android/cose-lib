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
 * Test class for testing {@link Ec2SigningKey}. Key values used in test cases are referenced from
 * https://datatracker.ietf.org/doc/html/rfc8152#appendix-C
 */
@RunWith(JUnit4.class)
public class Ec2KeyAgreementKeyTest {
  static final String X_COR = "5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE";
  static final String Y_COR = "B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
  static final String D_PARAM = "5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE";
  private static final byte[] X_BYTES = TestUtilities.hexStringToByteArray(X_COR);
  private static final byte[] Y_BYTES = TestUtilities.hexStringToByteArray(Y_COR);
  private static final byte[] D_BYTES = TestUtilities.hexStringToByteArray(D_PARAM);

  @Test
  public void testRoundTrip() throws CborException, CoseException {
    final byte[] keyId = TestUtilities.KEYID_BYTES;
    final Map map = new Map();
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_TYPE),
        new UnsignedInteger(Headers.KEY_TYPE_EC2));
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_ID), new ByteString(keyId));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_CURVE),
        new UnsignedInteger(Headers.CURVE_EC2_P256));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_X), new ByteString(X_BYTES));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_Y), new ByteString(Y_BYTES));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_D), new ByteString(D_BYTES));

    final Ec2KeyAgreementKey key = new Ec2KeyAgreementKey(map);
    byte[] a = key.serialize();

    final Ec2SigningKey newKey = Ec2SigningKey.parse(a);

    Assert.assertEquals(Headers.KEY_TYPE_EC2, newKey.getKeyType());
    Assert.assertArrayEquals(keyId, newKey.getKeyId());
    Assert.assertEquals(new UnsignedInteger(Headers.CURVE_EC2_P256),
        newKey.getLabels().get(Headers.KEY_PARAMETER_CURVE));
    Assert.assertEquals(new ByteString(X_BYTES), newKey.getLabels().get(Headers.KEY_PARAMETER_X));
    Assert.assertEquals(new ByteString(Y_BYTES), newKey.getLabels().get(Headers.KEY_PARAMETER_Y));
    Assert.assertEquals(new ByteString(D_BYTES), newKey.getLabels().get(Headers.KEY_PARAMETER_D));

    byte[] b = newKey.serialize();
    Assert.assertArrayEquals(a, b);
  }

  @Test
  public void testConversion() throws CborException, CoseException {
    final String cborString = "A4010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
        + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    final ByteString x = new ByteString(X_BYTES);
    final ByteString y = new ByteString(Y_BYTES);
    final Ec2KeyAgreementKey sKey = Ec2KeyAgreementKey.parse(
        TestUtilities.hexStringToByteArray(cborString));
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
    Ec2KeyAgreementKey key = Ec2KeyAgreementKey.builder()
        .withCurve(Headers.CURVE_EC2_P256)
        .withXCoordinate(X_BYTES)
        .withYCoordinate(Y_BYTES)
        .build();
    Assert.assertEquals(cborString, TestUtilities.bytesToHexString(key.serialize()));
  }

  @Test
  public void testBuilderFailureWrongOperation() throws CoseException {
    Ec2KeyAgreementKey.Builder builder = Ec2KeyAgreementKey.builder()
        .withCurve(Headers.CURVE_EC2_P256)
        .withXCoordinate(X_BYTES)
        .withYCoordinate(Y_BYTES);
    try {
      builder.withOperations(Headers.KEY_OPERATIONS_DECRYPT, Headers.KEY_OPERATIONS_SIGN);
      Assert.fail("Builder should fail on providing wrong operations.");
    } catch (CoseException e) {
      // pass
    }
  }

  @Test(expected = CoseException.class)
  public void testOkpKeyParsingInEc2KeyAgreementKey() throws CborException, CoseException {
    String cborString = "A401012006215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F"
        + "707511A2358209D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    Ec2KeyAgreementKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }

  @Test(expected = CoseException.class)
  public void testEc2KeyParsingWithIncorrectCurve() throws CborException, CoseException {
    String cborString = "A501022006215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F"
        + "707511A22402358209D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    Ec2KeyAgreementKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }

  @Test
  public void testKeyParsingWithNullDParameterBytes() throws CborException, CoseException {
    String cborString = "A5010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B6243"
        + "43167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC672340";
    // Even if D parameter is null, we don't care since it will not be used for key agreement.
    Ec2KeyAgreementKey.parse(TestUtilities.hexStringToByteArray(cborString));
  }
}
