package com.google.cose;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Abstract class for generic Ec2 key
 */
public abstract class OkpKey extends CoseKey {
  protected byte[] privateKeyBytes;
  protected byte[] publicKeyBytes;
  protected int curve;

  OkpKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);
    if (getKeyType() != Headers.KEY_TYPE_OKP) {
      throw new CoseException("Expecting OKP key (type 1), found type " + getKeyType());
    }
    populateKeyFromCbor();
  }

  void populateKeyFromCbor() throws CborException, CoseException {
    privateKeyBytes = getPrivateKeyBytesFromCbor();
    publicKeyBytes = getPublicKeyBytesFromCbor();
    curve = CborUtils.asInteger(labels.get(Headers.KEY_PARAMETER_CURVE));
  }

  private byte[] getPrivateKeyBytesFromCbor() throws CborException, CoseException {
    if (labels.containsKey(Headers.KEY_PARAMETER_D)) {
      byte[] keyMaterial = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_D)).getBytes();
      if (keyMaterial.length == 0) {
        throw new CoseException("Could not decode private key. Expected key material.");
      }
      return keyMaterial;
    }
    return null;
  }

  private byte[] getPublicKeyBytesFromCbor() throws CborException, CoseException {
    if (labels.containsKey(Headers.KEY_PARAMETER_X)) {
      byte[] keyMaterial = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_X)).getBytes();
      if (keyMaterial.length == 0) {
        throw new CoseException("Could not decode public key. Expected key material.");
      }
      return keyMaterial;
    }
    if (privateKeyBytes == null) {
      throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
    }
    return publicFromPrivate(privateKeyBytes);
  }


  protected abstract byte[] publicFromPrivate(byte[] privateKey) throws CoseException;

  public abstract PublicKey getPublicKey() throws CoseException;

  public abstract OkpKey getPublic() throws CborException, CoseException;

  public byte[] getPublicKeyBytes() {
    return Arrays.copyOf(publicKeyBytes, publicKeyBytes.length);
  }

  public int getCurve() {
    return curve;
  }

  /** Recursive builder to build out the Ec2 key and its subclasses. */
  abstract static class Builder<T extends Builder<T>> extends CoseKey.Builder<T> {
    private Integer curve = null;
    private byte[] dParameter;
    private byte[] xCor;

    boolean isKeyMaterialPresent() {
      return (dParameter != null && dParameter.length != 0) || (xCor != null && xCor.length != 0);
    }

    @Override
    void verifyKeyMaterialPresentAndComplete() throws CoseException {
      if (!isKeyMaterialPresent()) {
        throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
      }
    }

    @Override
    protected Map compile() throws CoseException {
      if (curve == null) {
        throw new CoseException("Need curve information.");
      }
      withKeyType(Headers.KEY_TYPE_OKP);

      Map cborKey = super.compile();

      cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_CURVE), new UnsignedInteger(curve));
      if (dParameter != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_D), new ByteString(dParameter));
      }
      if (xCor != null && xCor.length != 0) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_X), new ByteString(xCor));
      }
      return cborKey;
    }

    public T copyFrom(OkpKey key) {
      curve = key.curve;
      dParameter = key.privateKeyBytes;
      xCor = key.publicKeyBytes;
      return super.copyFrom(key);
    }

    public T withCurve(int curve) throws CoseException {
      if ((curve != Headers.CURVE_OKP_X25519) && (curve != Headers.CURVE_OKP_ED25519)) {
        throw new CoseException(CoseException.UNSUPPORTED_CURVE_EXCEPTION_MESSAGE);
      }
      this.curve = curve;
      return self();
    }

    public T withDParameter(byte[] dParam) {
      this.dParameter = dParam;
      return self();
    }

    public T withXCoordinate(byte[] xCor) {
      this.xCor = xCor;
      return self();
    }
  }
}
