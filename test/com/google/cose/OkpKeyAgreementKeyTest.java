/*
 * Copyright 2023 Google LLC
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
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.Headers;
import java.nio.charset.StandardCharsets;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test class for testing {@link OkpKeyAgreementKey}. */
@RunWith(JUnit4.class)
public class OkpKeyAgreementKeyTest {
  static final String X_VAL = "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A";
  private static final byte[] X_BYTES = TestUtilities.hexStringToByteArray(X_VAL);
  static final String D_VAL = "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A";
  private static final byte[] D_BYTES = TestUtilities.hexStringToByteArray(D_VAL);

  @Test
  public void testRoundTrip() throws CborException, CoseException {
    final byte[] keyId = "29".getBytes(StandardCharsets.UTF_8);
    final Map map = new Map();
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_TYPE),
        new UnsignedInteger(Headers.KEY_TYPE_OKP));
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_ID), new ByteString(keyId));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_CURVE),
        new UnsignedInteger(Headers.CURVE_OKP_X25519));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_X), new ByteString(X_BYTES));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_D), new ByteString(D_BYTES));

    final OkpKeyAgreementKey keyWithConstructor = new OkpKeyAgreementKey(map);
    OkpKeyAgreementKey keyWithBuilder = OkpKeyAgreementKey.builder()
        .withDParameter(D_BYTES)
        .withXCoordinate(X_BYTES)
        .withKeyId(keyId)
        .build();
    Assert.assertArrayEquals(keyWithConstructor.serialize(), keyWithBuilder.serialize());

    final OkpKeyAgreementKey rebuiltKey = OkpKeyAgreementKey.parse(keyWithConstructor.serialize());

    Assert.assertEquals(Headers.KEY_TYPE_OKP, rebuiltKey.getKeyType());
    Assert.assertEquals(new UnsignedInteger(Headers.CURVE_OKP_X25519),
        rebuiltKey.labels.get(Headers.KEY_PARAMETER_CURVE));
    Assert.assertEquals(new ByteString(X_BYTES), rebuiltKey.labels.get(Headers.KEY_PARAMETER_X));
    Assert.assertEquals(new ByteString(D_BYTES), rebuiltKey.labels.get(Headers.KEY_PARAMETER_D));

    Assert.assertArrayEquals(keyId, rebuiltKey.getKeyId());
    Assert.assertArrayEquals(keyWithConstructor.serialize(), rebuiltKey.serialize());
  }

  @Test
  public void testConversion() throws CborException, CoseException {
    final String cborString = "A4010120042158208520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA"
        + "4A98EAA9B4E6A23582077076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A";
    final OkpKeyAgreementKey sKey = OkpKeyAgreementKey.parse(TestUtilities.hexStringToByteArray(cborString));
    Assert.assertEquals(Headers.KEY_TYPE_OKP, sKey.getKeyType());
    Assert.assertEquals(new UnsignedInteger(Headers.CURVE_OKP_X25519),
        sKey.getLabels().get(Headers.KEY_PARAMETER_CURVE));
    Assert.assertEquals(new ByteString(X_BYTES), sKey.getLabels().get(Headers.KEY_PARAMETER_X));
    Assert.assertEquals(new ByteString(D_BYTES), sKey.getLabels().get(Headers.KEY_PARAMETER_D));
  }

  @Test
  public void testBuilder() throws CborException, CoseException {
    final String cborString = "A3010120042158208520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA"
        + "4A98EAA9B4E6A";
    OkpKeyAgreementKey key = OkpKeyAgreementKey.builder()
        .withXCoordinate(X_BYTES)
        .build();
    Assert.assertEquals(cborString, TestUtilities.bytesToHexString(key.serialize()));
  }

  @Test
  public void testBuilderPrivateKey() throws CborException, CoseException {
    final String cborString = "A4010120042158208520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA"
        + "4A98EAA9B4E6A23582077076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A";
    OkpKeyAgreementKey key = OkpKeyAgreementKey.builder()
        .withXCoordinate(X_BYTES)
        .withDParameter(D_BYTES)
        .build();
    Assert.assertEquals(cborString, TestUtilities.bytesToHexString(key.serialize()));
  }

  @Test
  public void testEmptyBuilderFailure() throws CborException {
    OkpKeyAgreementKey.Builder builder = OkpKeyAgreementKey.builder();
    assertThrows(
        "Expected failure when building on empty builder.",
        CoseException.class,
        () -> builder.build());
  }

  @Test
  public void testBuilderPassOnMissingX() throws CborException, CoseException {
    OkpKeyAgreementKey keyAgreementKey = OkpKeyAgreementKey.builder()
        .withDParameter(D_BYTES)
        .build();
    Assert.assertArrayEquals(keyAgreementKey.getPublicKeyBytes(), X_BYTES);
  }

  @Test
  public void testBuilderPassOnMissingD() throws CborException, CoseException {
    OkpKeyAgreementKey.builder()
        .withXCoordinate(X_BYTES)
        .build();
  }

  @Test
  public void testBuilderFailureOnWrongOperation() throws CborException, CoseException {
    OkpKeyAgreementKey.Builder builder = OkpKeyAgreementKey.builder()
        .withXCoordinate(X_BYTES)
        .withDParameter(D_BYTES);
    assertThrows(
        "Expected builder to fail with wrong operations.",
        CoseException.class,
        () -> builder.withOperations(Headers.KEY_OPERATIONS_DECRYPT, Headers.KEY_OPERATIONS_SIGN));
    builder.build();
  }

  @Test
  public void testEc2KeyParsingInOkpKeyAgreementKey() throws CborException {
    String cborString = "A4010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
        + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    assertThrows(
        CoseException.class,
        () -> OkpKeyAgreementKey.parse(TestUtilities.hexStringToByteArray(cborString)));
  }

  @Test
  public void testOkpKeyParsingWithIncorrectCurve() throws CborException {
    String cborString = "A4010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
        + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    assertThrows(
        CoseException.class,
        () -> OkpKeyAgreementKey.parse(TestUtilities.hexStringToByteArray(cborString)));
  }

  @Test
  public void testEmptyPrivateKeyBytes() throws CborException {
    String cborString = "A401012004215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F"
        + "707511A2340";
    assertThrows(
        CoseException.class,
        () -> OkpKeyAgreementKey.parse(TestUtilities.hexStringToByteArray(cborString)));
  }

  @Test
  public void testEmptyPublicKeyBytes() throws CborException {
    String cborString = "A40101200421402358209D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BA"
        + "C031CAE7F60";
    assertThrows(
        CoseException.class,
        () -> OkpKeyAgreementKey.parse(TestUtilities.hexStringToByteArray(cborString)));
  }

  @Test
  public void testOkpGeneratedKey_verificationWithSignature() throws CborException, CoseException {
    OkpKeyAgreementKey okpKey =
        OkpKeyAgreementKey.generateKey(Algorithm.ECDH_ES_HKDF_256, Headers.CURVE_OKP_X25519);
  }
}
