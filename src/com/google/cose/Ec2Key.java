package com.google.cose;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import com.google.cose.utils.Headers;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

/**
 * Abstract class for generic Ec2 key
 */
public abstract class Ec2Key extends CoseKey {
  private static final int SIGN_POSITIVE = 1;

  protected KeyPair keyPair;

  Ec2Key(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);
    populateKeyFromCbor();
  }

  void populateKeyFromCbor() throws CborException, CoseException {
    if (getKeyType() != Headers.KEY_TYPE_EC2) {
      throw new CoseException("Expecting EC2 key (type 2), found type " + getKeyType());
    }

    // Get curve information
    int curve = CborUtils.asInteger(labels.get(Headers.KEY_PARAMETER_CURVE));

    // Get private key.
    final ECPrivateKey privateKey;
    if (labels.containsKey(Headers.KEY_PARAMETER_D)) {
      byte[] key = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_D)).getBytes();
      if (key.length == 0) {
        throw new CoseException("Cannot decode private key. Missing coordinate information.");
      }
      privateKey = CoseUtils.getEc2PrivateKeyFromInteger(curve, new BigInteger(SIGN_POSITIVE, key));
    } else {
      privateKey = null;
    }

    if (!labels.containsKey(Headers.KEY_PARAMETER_X)) {
      if (privateKey == null) {
        throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
      } else {
        keyPair = new KeyPair(
            CoseUtils.getEc2PublicKeyFromPrivateKey(curve, privateKey),
            privateKey);
        return;
      }
    }

    final ByteString xCor = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_X));
    // Get the public key for EC2 key.
    // We should not have a case where x is provided but y is not.
    if (!labels.containsKey(Headers.KEY_PARAMETER_Y)) {
      throw new IllegalStateException("X coordinate provided but Y coordinate is missing.");
    }
    final ByteString yCor = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_Y));
    final PublicKey publicKey = CoseUtils.getEc2PublicKeyFromCoordinates(
        curve,
        new BigInteger(SIGN_POSITIVE, xCor.getBytes()),
        new BigInteger(SIGN_POSITIVE, yCor.getBytes())
    );
    keyPair = new KeyPair(publicKey, privateKey);
  }

  public ECPublicKey getPublicKey() {
    return (ECPublicKey) this.keyPair.getPublic();
  }

  void verifyAlgorithmAllowedByKey(Algorithm algorithm) throws CborException, CoseException {
    Map keyMap = CborUtils.asMap(encode());
    int curve = CborUtils.asInteger(keyMap.get(new NegativeInteger(Headers.KEY_PARAMETER_CURVE)));
    boolean compatible;
    switch (curve) {
      case Headers.CURVE_EC2_P256:
        compatible = algorithm == Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256;
        break;
      case Headers.CURVE_EC2_P384:
        compatible = (algorithm == Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_384);
        break;
      case Headers.CURVE_EC2_P521:
        compatible = (algorithm == Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_512);
        break;
      default:
        throw new CoseException("Unsupported curve.");
    }
    if (!compatible) {
      throw new CoseException("Algorithm not compatible with Ec2 key.");
    }
  }

  // Big endian: Do not reuse for little endian encodings
  private static byte[] arrayFromBigNum(BigInteger num, int keySize)
      throws IllegalArgumentException {
    // Roundup arithmetic from bits to bytes.
    byte[] keyBytes = new byte[(keySize + 7) / 8];
    byte[] keyBytes2 = num.toByteArray();
    if (keyBytes.length == keyBytes2.length) {
      return keyBytes2;
    }
    if (keyBytes2.length > keyBytes.length) {
      // There should be no more than one padding(0) byte, invalid key otherwise.
      if (keyBytes2.length - keyBytes.length > 1 && keyBytes2[0] != 0) {
        throw new IllegalArgumentException();
      }
      System.arraycopy(keyBytes2, keyBytes2.length - keyBytes.length, keyBytes, 0, keyBytes.length);
    } else {
      System.arraycopy(
          keyBytes2, 0, keyBytes, keyBytes.length - keyBytes2.length, keyBytes2.length);
    }
    return keyBytes;
  }

  /** Recursive builder to build out the Ec2 key and its subclasses. */
  abstract static class Builder<T extends Builder<T>> extends CoseKey.Builder<T> {
    private Integer curve = null;
    private byte[] dParameter;
    private byte[] xCor;
    private byte[] yCor;

    @Override
    void verifyKeyMaterialPresentAndComplete() throws CoseException {
      if (!isKeyMaterialPresent()) {
        throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
      }
      if (isPublicKeyMaterialIncomplete()) {
        throw new CoseException("Both coordinates of public key need to be provided.");
      }
    }

    boolean isKeyMaterialPresent() {
      return dParameter != null || (xCor != null && yCor != null);
    }

    boolean isPublicKeyMaterialIncomplete() {
      return xCor == null ^ yCor == null;
    }

    @Override
    protected Map compile() throws CoseException {
      if (curve == null) {
        throw new CoseException("Need curve information.");
      }
      withKeyType(Headers.KEY_TYPE_EC2);

      Map cborKey = super.compile();

      cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_CURVE), new UnsignedInteger(curve));
      if (dParameter != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_D), new ByteString(dParameter));
      }
      if (xCor != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_X), new ByteString(xCor));
      }
      if (yCor != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_Y), new ByteString(yCor));
      }
      return cborKey;
    }

    public T withCurve(int curve) throws CoseException {
      if ((curve < 0) || (curve > Headers.CURVE_EC2_P521)) {
        throw new CoseException(CoseException.UNSUPPORTED_CURVE_EXCEPTION_MESSAGE);
      }
      this.curve = curve;
      return self();
    }

    public T withXCoordinate(byte[] xCor) {
      this.xCor = xCor;
      return self();
    }

    public T withYCoordinate(byte[] yCor) {
      this.yCor = yCor;
      return self();
    }

    public T withGeneratedKeyPair(int curve) throws CoseException {
      KeyPair keyPair;
      int keySize;
      String curveName;

      switch (curve) {
        case Headers.CURVE_EC2_P256:
          curveName = "secp256r1";
          keySize = 256;
          break;

        case Headers.CURVE_EC2_P384:
          curveName = "secp384r1";
          keySize = 384;
          break;

        case Headers.CURVE_EC2_P521:
          curveName = "secp521r1";
          keySize = 521;
          break;

        default:
          throw new CoseException("Unsupported curve: " + curve);
      }
      try {
        ECGenParameterSpec paramSpec = new ECGenParameterSpec(curveName);
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(paramSpec);
        keyPair = gen.genKeyPair();
        ECPoint pubPoint = ((ECPublicKey) keyPair.getPublic()).getW();

        return withPrivateKeyRepresentation()
            .withPkcs8EncodedBytes(keyPair.getPrivate().getEncoded())
            .withXCoordinate(arrayFromBigNum(pubPoint.getAffineX(), keySize))
            .withYCoordinate(arrayFromBigNum(pubPoint.getAffineY(), keySize))
            .withCurve(curve);
      } catch (GeneralSecurityException e) {
        throw new CoseException("Failed to generate key pari for  curve: " + curve, e);
      }
    }

    public PrivateKeyRepresentationBuilder<T> withPrivateKeyRepresentation() {
      return new PrivateKeyRepresentationBuilder<T>(this);
    }

    /**
     * Helper class to get the raw bytes out of the encoded private keys.
     */
    public static class PrivateKeyRepresentationBuilder<T extends Builder<T>> {
      Builder<T> builder;

      PrivateKeyRepresentationBuilder(Builder<T> builder) {
        this.builder = builder;
      }

      public T withPrivateKey(ECPrivateKey privateKey) {
        builder.dParameter = privateKey.getS().toByteArray();
        return builder.self();
      }

      public T withPkcs8EncodedBytes(byte[] keyBytes) throws CoseException {
        ECPrivateKey key = CoseUtils.getEc2PrivateKeyFromEncodedKeyBytes(keyBytes);
        builder.dParameter = key.getS().toByteArray();
        return builder.self();
      }

      /**
       * This function expects the BigInteger byte array of the private key. This is typically the
       * multiplier in the EC2 private key which can generate EC2 public key from generator point.
       * @param rawBytes byte array representation of BigInteger
       * @return {@link Builder}
       */
      public T withDParameter(byte[] rawBytes) {
        builder.dParameter = rawBytes;
        return builder.self();
      }
    }
  }
}
