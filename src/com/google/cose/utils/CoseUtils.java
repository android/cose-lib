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

package com.google.cose.utils;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.common.collect.ImmutableMap;
import com.google.cose.CoseKey;
import com.google.cose.Ec2SigningKey;
import com.google.cose.Encrypt0Message;
import com.google.cose.EncryptionKey;
import com.google.cose.Mac0Message;
import com.google.cose.MacKey;
import com.google.cose.OkpSigningKey;
import com.google.cose.Sign1Message;
import com.google.cose.exceptions.CoseException;
import com.google.cose.structure.EncryptStructure;
import com.google.cose.structure.EncryptStructure.EncryptionContext;
import com.google.cose.structure.MacStructure;
import com.google.cose.structure.MacStructure.MacContext;
import com.google.cose.structure.SignStructure;
import com.google.cose.structure.SignStructure.SignatureContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.jce.ECNamedCurveTable;

public class CoseUtils {
  private static final String EC_PARAMETER_SPEC = "EC";

  public static DataItem encodeStructure(String context, Map protectedBodyHeaders,
      Map protectedSignHeaders, byte[] externalAad, byte[] payload) throws CborException {
    ArrayBuilder<CborBuilder> arrayBuilder = new CborBuilder().addArray();
    arrayBuilder.add(context);
    arrayBuilder.add(serializeProtectedHeaders(protectedBodyHeaders));
    if (protectedSignHeaders != null) {
      arrayBuilder.add(serializeProtectedHeaders(protectedSignHeaders));
    }
    arrayBuilder.add((externalAad != null) ? externalAad : new byte[0]);
    if (payload != null) {
      arrayBuilder.add(payload);
    }
    return arrayBuilder.end().build().get(0);
  }

  public static ImmutableMap<Integer, DataItem> getLabelsFromMap(Map keyMap) throws CborException {
    final ImmutableMap.Builder<Integer, DataItem> labels = ImmutableMap.builder();
    for (DataItem item : keyMap.getKeys()) {
      labels.put(CborUtils.asInteger(item), keyMap.get(item));
    }
    return labels.build();
  }

  /**
   * Returns DataItem from a cbor map based on Integer value.
   * @param cborMap map that has the information.
   * @param value integer to be used as key in the map.
   * @return value in the map corresponding to key
   */
  public static DataItem getValueFromMap(Map cborMap, int value) {
    final Number key;
    if (value >= 0) {
      key = new UnsignedInteger(value);
    } else {
      key = new NegativeInteger(value);
    }
    return cborMap.get(key);
  }

  public static ECPrivateKey getEc2PrivateKeyFromEncodedKeyBytes(byte[] encodedPrivateKeyBytes)
      throws CoseException {
    try {
      KeyFactory kf = KeyFactory.getInstance(EC_PARAMETER_SPEC);
      return (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKeyBytes));
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new CoseException("Error while generating key from d parameter.", e);
    }
  }

  public static ECPrivateKey getEc2PrivateKeyFromInteger(int curve, BigInteger s)
      throws CoseException {
    try {
      AlgorithmParameters params = AlgorithmParameters.getInstance(EC_PARAMETER_SPEC);
      params.init(new ECGenParameterSpec(getEc2CoseCurveName(curve)));
      ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);

      KeyFactory keyFactory = KeyFactory.getInstance(EC_PARAMETER_SPEC);
      return (ECPrivateKey) keyFactory.generatePrivate(new ECPrivateKeySpec(s, ecParameters));
    } catch (NoSuchAlgorithmException
        | InvalidParameterSpecException
        | InvalidKeySpecException e) {
      throw new CoseException("Error while generating key from raw bytes.", e);
    }
  }

  /**
   * Gets EC2 Public Key from x and y coordinate values.
   *
   * Only supports P256 curve currently.
   * @param curve supported curve
   * @param x raw bytes for x coordinate.
   * @param y raw bytes for y coordinate.
   * @return PublicKey JCA implementation
   * @throws CoseException if unsupported key curve is used.
   */
  public static PublicKey getEc2PublicKeyFromCoordinates(int curve, BigInteger x, BigInteger y)
      throws CoseException {
    try {
      final AlgorithmParameters params = AlgorithmParameters.getInstance(EC_PARAMETER_SPEC);
      params.init(new ECGenParameterSpec(getEc2CoseCurveName(curve)));
      final ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);

      final ECPoint ecPoint = new ECPoint(x, y);
      final ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, ecParameters);
      return KeyFactory.getInstance(EC_PARAMETER_SPEC).generatePublic(keySpec);
    } catch (final InvalidParameterSpecException | InvalidKeySpecException
        | NoSuchAlgorithmException ex) {
      throw new IllegalStateException("Unexpected error", ex);
    }
  }

  private static String getEc2CoseCurveName(int coseCurveId) throws CoseException {
    switch (coseCurveId) {
      case Headers.CURVE_EC2_P256:
        return "secp256r1";
      case Headers.CURVE_EC2_P384:
        return "secp384r1";
      case Headers.CURVE_EC2_P521:
        return "secp521r1";
      default:
        throw new CoseException("Unsupported Curve.");
    }
  }

  public static Map asProtectedHeadersMap(DataItem serialProtectedHeaders) throws CborException {
    byte[] protectedHeaderBytes = CborUtils.asByteString(serialProtectedHeaders).getBytes();
    return asProtectedHeadersMap(protectedHeaderBytes);
  }

  public static Map asProtectedHeadersMap(byte[] protectedHeaderBytes) throws CborException {
    if (protectedHeaderBytes.length == 0) {
      return new Map();
    }
    return CborUtils.asMap(CborUtils.decode(protectedHeaderBytes));
  }

  public static byte[] serializeProtectedHeaders(Map protectedHeaders) throws CborException {
    if (protectedHeaders.getKeys().size() == 0) {
      return new byte[0];
    }
    return CborUtils.encode(protectedHeaders);
  }

  public static byte[] getBytesFromBstrOrNilValue(DataItem item) throws CborException, CoseException {
    if (item.getMajorType() == MajorType.BYTE_STRING) {
      return CborUtils.asByteString(item).getBytes();
    } else if (CborUtils.isNull(item)) {
      return null;
    } else {
      throw new CoseException("Error while decoding CBOR. Expected bstr/nil value.");
    }
  }

  public static PublicKey getEc2PublicKeyFromPrivateKey(int curve, ECPrivateKey privateKey)
      throws CoseException {
    org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec =
        ECNamedCurveTable.getParameterSpec(getEc2CoseCurveName(curve));
    org.bouncycastle.math.ec.ECPoint Q = ecParameterSpec.getG().multiply(privateKey.getS());
    Q = Q.normalize();
    return getEc2PublicKeyFromCoordinates(
        curve,
        Q.getAffineXCoord().toBigInteger(),
        Q.getAffineYCoord().toBigInteger());
  }

  public static Mac0Message generateCoseMac0(MacKey key, Map protectedHeaders,
      Map unprotectedHeaders, byte[] payloadMessage, byte[] detachedContent, Algorithm algorithm)
      throws CborException, CoseException {
    byte[] message = getMessageFromDetachedOrPayload(payloadMessage, detachedContent);

    return Mac0Message.builder()
        .withProtectedHeaders(protectedHeaders)
        .withMessage(payloadMessage)
        .withTag(key.createMac(
            new MacStructure(MacContext.MAC0, protectedHeaders, new byte[0], message).serialize(),
            algorithm))
        .withUnprotectedHeaders(unprotectedHeaders)
        .build();
  }

  public static boolean verifyCoseMac0(MacKey key, Mac0Message message, byte[] detachedContent,
      Algorithm algorithm) throws CborException, CoseException {
    byte[] macedMessage = getMessageFromDetachedOrPayload(message.getMessage(), detachedContent);
    byte[] toBeMaced = new MacStructure(MacContext.MAC0, message.getProtectedHeaders(), new byte[0],
        macedMessage).serialize();
    if (algorithm == null) {
      algorithm = Algorithm.fromCoseAlgorithmId(
          CborUtils.asInteger(
              message.findAttributeInProtectedHeaders(Headers.MESSAGE_HEADER_ALGORITHM)
          )
      );
    }
    return key.verifyMac(toBeMaced, algorithm, message.getTag());
  }

  public static Encrypt0Message generateCoseEncrypt0(EncryptionKey key, Map protectedHeaders,
      Map unprotectedHeaders, byte[] message, byte[] externalAad, byte[] iv, Algorithm algorithm)
      throws CborException, CoseException {
    return Encrypt0Message.builder()
        .withProtectedHeaders(protectedHeaders)
        .withUnprotectedHeaders(unprotectedHeaders)
        .withCiphertext(
            key.encrypt(algorithm, message, iv, new EncryptStructure(
                EncryptionContext.ENCRYPT0, protectedHeaders, externalAad).serialize())
        ).build();
  }

  public static Sign1Message generateCoseSign1(CoseKey key, Map protectedHeaders,
      Map unprotectedHeaders, byte[] payloadMessage, byte[] detachedContent, byte[] externalAad,
      Algorithm algorithm) throws CborException, CoseException {
    if (!(key instanceof Ec2SigningKey || key instanceof OkpSigningKey)) {
      throw new CoseException("Incompatible key used.");
    }
    byte[] message = getMessageFromDetachedOrPayload(payloadMessage, detachedContent);

    byte[] toBeSigned = new SignStructure(
        SignatureContext.SIGNATURE1, protectedHeaders, null, externalAad, message
    ).serialize();

    byte[] signature;
    if (key instanceof OkpSigningKey) {
      signature = ((OkpSigningKey) key).sign(algorithm, toBeSigned);
    } else {
      signature = signatureDerToCose(
          ((Ec2SigningKey) key).sign(algorithm, toBeSigned, null),
          algorithm);
    }

    return Sign1Message.builder()
        .withProtectedHeaders(protectedHeaders)
        .withUnprotectedHeaders(unprotectedHeaders)
        .withMessage(message)
        .withSignature(signature)
        .build();
  }

  public static void verifyCoseSign1Message(CoseKey key, Sign1Message message,
      byte[] detachedContent, byte[] externalAad, Algorithm algorithm)
      throws CborException, CoseException {
    if (!(key instanceof Ec2SigningKey || key instanceof OkpSigningKey)) {
      throw new CoseException("Incompatible key used.");
    }

    if (algorithm == null) {
      Integer alg = key.getAlgorithm();
      if (alg == null) {
        throw new CoseException(
            "No algorithm provided, and Cosekey does not contain any algorithm either.");
      }
      algorithm = Algorithm.fromCoseAlgorithmId(alg.intValue());
    }

    Map protectedHeaders = message.getProtectedHeaders();
    byte[] signedMessage = getMessageFromDetachedOrPayload(message.getMessage(), detachedContent);

    byte[] encodedStructure = new SignStructure(
        SignatureContext.SIGNATURE1, protectedHeaders, null, externalAad, signedMessage
    ).serialize();
    if (key instanceof Ec2SigningKey) {
      byte[] signature = signatureCoseToDer(message.getSignature());
      ((Ec2SigningKey) key).verify(algorithm, encodedStructure, signature, null);
    } else {
      ((OkpSigningKey) key).verify(algorithm, encodedStructure, message.getSignature());
    }
  }

  private static byte[] signatureCoseToDer(byte[] signature) {
    // r and s are always positive and may use all bits so use the constructor which
    // parses them as unsigned.
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(
        signature, 0, signature.length / 2));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(
        signature, signature.length / 2, signature.length));

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      DERSequenceGenerator seq = new DERSequenceGenerator(baos);
      seq.addObject(new ASN1Integer(r.toByteArray()));
      seq.addObject(new ASN1Integer(s.toByteArray()));
      seq.close();
    } catch (IOException e) {
      throw new IllegalStateException("Error generating DER signature", e);
    }
    return baos.toByteArray();
  }

  /*
   * From RFC 8152 section 8.1 ECDSA:
   *
   * The signature algorithm results in a pair of integers (R, S).  These
   * integers will be the same length as the length of the key used for
   * the signature process.  The signature is encoded by converting the
   * integers into byte strings of the same length as the key size.  The
   * length is rounded up to the nearest byte and is left padded with zero
   * bits to get to the correct length.  The two integers are then
   * concatenated together to form a byte string that is the resulting
   * signature.
   */
  private static byte[] signatureDerToCose(byte[] signature, Algorithm algorithm)
      throws CoseException {
    ASN1Primitive asn1;
    try {
      asn1 = new ASN1InputStream(new ByteArrayInputStream(signature)).readObject();
    } catch (IOException e) {
      throw new IllegalArgumentException("Error decoding DER signature", e);
    }
    if (!(asn1 instanceof ASN1Sequence)) {
      throw new IllegalArgumentException("Not a ASN1 sequence");
    }
    ASN1Encodable[] asn1Encodables = ((ASN1Sequence) asn1).toArray();
    if (asn1Encodables.length != 2) {
      throw new IllegalArgumentException("Expected two items in sequence");
    }
    if (!(asn1Encodables[0].toASN1Primitive() instanceof ASN1Integer)) {
      throw new IllegalArgumentException("First item is not an integer");
    }
    BigInteger r = ((ASN1Integer) asn1Encodables[0].toASN1Primitive()).getValue();
    if (!(asn1Encodables[1].toASN1Primitive() instanceof ASN1Integer)) {
      throw new IllegalArgumentException("Second item is not an integer");
    }
    BigInteger s = ((ASN1Integer) asn1Encodables[1].toASN1Primitive()).getValue();

    byte[] rBytes = stripLeadingZeroes(r.toByteArray());
    byte[] sBytes = stripLeadingZeroes(s.toByteArray());
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    int keySize = getKeySizeFromAlgorithm(algorithm);
    try {
      for (int n = 0; n < keySize - rBytes.length; n++) {
        baos.write(0x00);
      }
      baos.write(rBytes);
      for (int n = 0; n < keySize - sBytes.length; n++) {
        baos.write(0x00);
      }
      baos.write(sBytes);
    } catch (IOException e) {
      throw new CoseException("Error while converting signature to cose spec.", e);
    }
    return baos.toByteArray();
  }

  private static int getKeySizeFromAlgorithm(Algorithm algorithm) {
    switch (algorithm) {
      case SIGNING_ALGORITHM_ECDSA_SHA_256:
        return 32;
      case SIGNING_ALGORITHM_ECDSA_SHA_384:
        return 48;
      case SIGNING_ALGORITHM_ECDSA_SHA_512:
        return 64;
      default:
        throw new IllegalArgumentException("Unsupported algorithm " + algorithm);
    }
  }

  private static byte[] stripLeadingZeroes(byte[] value) {
    for (int i = 0; i < value.length; i++) {
      if (value[i] != 0x00) {
        return Arrays.copyOfRange(value, i, value.length);
      }
    }
    return new byte[0];
  }

  private static byte[] getMessageFromDetachedOrPayload(byte[] payloadMessage,
      byte[] detachedContent) throws CoseException {
    int payloadLen = payloadMessage == null ? 0 : payloadMessage.length;
    int contentLen = detachedContent == null ? 0 : detachedContent.length;
    if (payloadLen > 0 && contentLen > 0) {
      throw new CoseException("Both detached content and payload cannot be non-empty.");
    }
    if (payloadLen > 0) {
      return payloadMessage;
    } else if (contentLen > 0) {
      return detachedContent;
    } else {
      throw new CoseException("Need message bytes to generate signature.");
    }
  }

  // Avoiding instantiation of the class
  private CoseUtils() {}
}
