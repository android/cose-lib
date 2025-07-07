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
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Abstract class for generic Ec2 key
 */
public abstract class OkpKey extends CoseKey {
  private byte[] publicKeyBytes;

  OkpKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);
    if (getKeyType() != Headers.KEY_TYPE_OKP) {
      throw new CoseException("Expecting OKP key (type 1), found type " + getKeyType());
    }
    populateKeyFromCbor();
  }

  void populateKeyFromCbor() throws CborException, CoseException {
    if (labels.containsKey(Headers.KEY_PARAMETER_X)) {
      byte[] keyMaterial = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_X)).getBytes();
      if (keyMaterial.length == 0) {
        throw new CoseException("Could not decode public key. Expected key material.");
      }
      publicKeyBytes = keyMaterial;
    } else {
      throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
    }
  }

  public byte[] getPublicKeyBytes() {
    return Arrays.copyOf(publicKeyBytes, publicKeyBytes.length);
  }

  public BigInteger getPublicKeyBytesAsBigInteger() {
    // Reverse the bytes to get the correct big-endian representation.
    byte[] reversedBytes = new byte[publicKeyBytes.length];
    for (int i = 0; i < publicKeyBytes.length; i++) {
      reversedBytes[i] = publicKeyBytes[publicKeyBytes.length - 1 - i];
    }
    return new BigInteger(1, reversedBytes);
  }
  
  /** Recursive builder to build out the Ec2 key and its subclasses. */
  abstract static class Builder<T extends Builder<T>> extends CoseKey.Builder<T> {
    private Integer curve = null;
    private byte[] xCor;

    boolean isKeyMaterialPresent() {
      return xCor != null && xCor.length != 0;
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
      if (xCor != null && xCor.length != 0) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_X), new ByteString(xCor));
      }
      return cborKey;
    }

    public T withCurve(int curve) throws CoseException {
      if ((curve != Headers.CURVE_OKP_X25519) && (curve != Headers.CURVE_OKP_ED25519)) {
        throw new CoseException(CoseException.UNSUPPORTED_CURVE_EXCEPTION_MESSAGE);
      }
      this.curve = curve;
      return self();
    }

    public T withXCoordinate(byte[] xCor) {
      this.xCor = xCor;
      return self();
    }
  }
}
