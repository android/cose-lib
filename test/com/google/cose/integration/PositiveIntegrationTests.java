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

package com.google.cose.integration;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.Ec2SigningKey;
import com.google.cose.Encrypt0Message;
import com.google.cose.EncryptionKey;
import com.google.cose.MacKey;
import com.google.cose.OkpSigningKey;
import com.google.cose.TestUtilities;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CoseUtils;
import com.google.cose.utils.Headers;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test class for testing {@link Ec2SigningKey}
 */
@RunWith(JUnit4.class)
public class PositiveIntegrationTests {
  @Test
  public void testOkpSigningAndVerificationWithRawKeyBytes() throws CborException, CoseException {
    String signatureVal = "0B99150FB1E436F619676BF879B3439B07C3C29CA17DD59AE2204C36950FABEE227430D"
        + "F3EC2EEB4605073083213CB857D851D9CE472D0EB285E31266034200B";
    String privateKey = "7D1FC441FE95424821D689CE0F93384D61A927FECA5D736F61E98D95C0CDC723";
    String publicKey = "D2AF809C76C0E970B1B1B338DCFC5833D3EAD36503545C187B262FA4ECF3E156";
    OkpSigningKey key = OkpSigningKey.builder()
        .withXCoordinate(TestUtilities.hexStringToByteArray(publicKey))
        .withDParameter(TestUtilities.hexStringToByteArray(privateKey))
        .build();
    byte[] signature = key.sign(Algorithm.SIGNING_ALGORITHM_EDDSA, TestUtilities.CONTENT_BYTES);
    Assert.assertEquals(signatureVal, TestUtilities.bytesToHexString(signature));

    key.verify(Algorithm.SIGNING_ALGORITHM_EDDSA, TestUtilities.CONTENT_BYTES, signature);
  }

  @Test
  public void testEc2SignAndVerifyWithPkcs8EncodedKeyBytesJCE() throws CborException, CoseException {
    byte[] message = TestUtilities.CONTENT_BYTES;
    String x = "4A6C8B7DF241AD4AB03BE78F5AFCAD498496B28B93DC4FA01353CD3848A0A9A7";
    String y = "BCB5A7A766DEF13A8DA6A54101062630DA04F486EA44A28A25AB3D6C0722B5C2";
    String priEncStr = "3041020100301306072A8648CE3D020106082A8648CE3D030107042730250201010420DE7B726"
        + "1710775352BF3C0669FA54229D9B2998EE9265645A3AF9F2FEFC93968";
    byte[] priEnc = TestUtilities.hexStringToByteArray(priEncStr);
    Ec2SigningKey key = Ec2SigningKey.builder()
        .withPrivateKeyRepresentation().withPkcs8EncodedBytes(priEnc)
        .withXCoordinate(TestUtilities.hexStringToByteArray(x))
        .withYCoordinate(TestUtilities.hexStringToByteArray(y))
        .withCurve(Headers.CURVE_EC2_P256)
        .build();
    byte[] signature = key.sign(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256, message, null);
    key.verify(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256, message, signature, null);
  }

  @Test
  public void testEc2SignAndVerifyWithPkcs8EncodedKeyBytesBC() throws CborException, CoseException {
    Security.addProvider(new BouncyCastleProvider());
    byte[] message = TestUtilities.CONTENT_BYTES;
    String x = "7578E06A498E413E548B9CC39D5A606BD00DE7F6AA71D81439698F60F8785DA0";
    String y = "38781826E5B085CFEC878FACA17FA378CE310259E72EE19C5F743AF0647959A1";
    String priEncStr = "308193020100301306072A8648CE3D020106082A8648CE3D030107047930770201010420DB"
        + "21CE777876E3CF26BCCE2E46892C7DBC9145438FB5500A9B716ADEB2A146A6A00A06082A8648CE3D030107A"
        + "144034200047578E06A498E413E548B9CC39D5A606BD00DE7F6AA71D81439698F60F8785DA038781826E5B0"
        + "85CFEC878FACA17FA378CE310259E72EE19C5F743AF0647959A1";
    byte[] priEnc = TestUtilities.hexStringToByteArray(priEncStr);
    Ec2SigningKey key = Ec2SigningKey.builder()
        .withPrivateKeyRepresentation().withPkcs8EncodedBytes(priEnc)
        .withXCoordinate(TestUtilities.hexStringToByteArray(x))
        .withYCoordinate(TestUtilities.hexStringToByteArray(y))
        .withCurve(Headers.CURVE_EC2_P256)
        .build();
    byte[] signature = key.sign(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256, message, "BC");
    key.verify(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256, message, signature, "BC");
  }

  @Test
  public void testEncryptionAndDecryptionWithRawKeyBytes() throws CborException, CoseException {
    byte[] message = TestUtilities.CONTENT_BYTES;
    byte[] keyMaterial = "1234567890abcdef1234567890abcdef".getBytes(StandardCharsets.UTF_8);
    EncryptionKey key = EncryptionKey.builder().withSecretKey(keyMaterial).build();
    byte[] iv = "abcdef0123456789".getBytes(StandardCharsets.UTF_8);
    byte[] aad = "this is aad".getBytes(StandardCharsets.UTF_8);
    byte[] ciphertext = key.encrypt(Algorithm.ENCRYPTION_AES_256_GCM, message, iv, aad);
    byte[] recoveredMessage = key.decrypt(Algorithm.ENCRYPTION_AES_256_GCM, ciphertext, iv, aad);
    Assert.assertArrayEquals(message, recoveredMessage);
  }

  @Test
  public void testMacCreateAndVerifyWithRawKeyBytes() throws CborException, CoseException {
    byte[] message = TestUtilities.CONTENT_BYTES;
    byte[] keyMaterial = "1234567890abcdef1234567890abcdef".getBytes(StandardCharsets.UTF_8);
    String expectedTag = "A0996BA1613EDE030284B89C9F5E68808584182CCD43866A65466627246AFD6A";
    MacKey key = MacKey.builder().withSecretKey(keyMaterial).build();
    byte[] tag = key.createMac(message, Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256);
    key.verifyMac(message, Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256, tag);
    Assert.assertEquals(expectedTag, TestUtilities.bytesToHexString(tag));
  }

  @Test
  public void testDecryptionOfEncrypt0Message() throws CborException, CoseException {
    String cborKeyString = "A301040258246D65726961646F632E6272616E64796275636B406275636B6C616E642E"
        + "6578616D706C6520582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D";
    EncryptionKey key = EncryptionKey.parse(TestUtilities.hexStringToByteArray(cborKeyString));
    SecureRandom random = new SecureRandom();
    Algorithm algorithm = Algorithm.ENCRYPTION_AES_256_GCM;
    byte[] iv = new byte[12];
    random.nextBytes(iv);
    Map unprotectedHeader = new Map();
    unprotectedHeader.put(new UnsignedInteger(Headers.MESSAGE_HEADER_BASE_IV),
        new ByteString(iv));
    Map protectedHeaders = new Map();
    protectedHeaders.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        algorithm.getCoseAlgorithmId());
    Encrypt0Message encrypt0Message = CoseUtils.generateCoseEncrypt0(key, protectedHeaders,
        unprotectedHeader, TestUtilities.CONTENT_BYTES, null, iv, algorithm);
    byte[] recoveredMessage = encrypt0Message.decrypt(key, null, null, null);
    Assert.assertArrayEquals(TestUtilities.CONTENT_BYTES, recoveredMessage);
  }
}
