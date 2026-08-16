package com.google.cose;

import static com.google.crypto.tink.subtle.SubtleUtil.bytes2Integer;

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
import java.security.interfaces.ECPublicKey;

/**
 * Abstract class for generic Ec2 key
 */
public abstract class Ec2Key extends CoseKey {
  private ECPublicKey publicKey;

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

    if (!labels.containsKey(Headers.KEY_PARAMETER_X)) {
      throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
    }

    final ByteString xCor = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_X));
    // Get the public key for EC2 key.
    // We should not have a case where x is provided but y is not.
    if (!labels.containsKey(Headers.KEY_PARAMETER_Y)) {
      throw new IllegalStateException("X coordinate provided but Y coordinate is missing.");
    }
    final ByteString yCor = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_Y));
    publicKey =
        (ECPublicKey)
            CoseUtils.getEc2PublicKeyFromCoordinates(
                curve, bytes2Integer(xCor.getBytes()), bytes2Integer(yCor.getBytes()));
  }

  public ECPublicKey getPublicKey() {
    return publicKey;
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

  /** Recursive builder to build out the Ec2 key and its subclasses. */
  abstract static class Builder<T extends Builder<T>> extends CoseKey.Builder<T> {
    private Integer curve = null;
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
      return xCor != null && yCor != null;
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
  }
}
