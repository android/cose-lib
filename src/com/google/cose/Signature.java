package com.google.cose;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import java.util.List;

/**
 * Encodes the COSE_Signature structure.
 */
public class Signature extends CoseMessage {
  private final byte[] signature;

  Signature(byte[] protectedHeaderBytes, Map unprotectedHeaders, byte[] signature) {
    super(protectedHeaderBytes, unprotectedHeaders);
    this.signature = signature;
  }

  static class Builder {
    private byte[] protectedHeaderBytes;
    private Map unprotectedHeaders;
    private byte[] signature;

    public Signature build() {
      if ((protectedHeaderBytes != null) && (unprotectedHeaders != null) && (signature != null)) {
        return new Signature(protectedHeaderBytes, unprotectedHeaders, signature);
      } else {
        throw new CoseException("Some fields are missing.");
      }
    }

    public Builder withProtectedHeaderBytes(byte[] protectedHeaderBytes) {
      this.protectedHeaderBytes = protectedHeaderBytes;
      return this;
    }

    public Builder withUnprotectedHeaders(Map unprotectedHeaders) {
      this.unprotectedHeaders = unprotectedHeaders;
      return this;
    }

    public Builder withSignature(byte[] signature) {
      this.signature = signature;
      return this;
    }
  }

  @Override
  public DataItem encode() {
    ArrayBuilder<CborBuilder> signArrayBuilder = new CborBuilder().addArray();
    signArrayBuilder.add(getProtectedHeaderBytes()).add(getUnprotectedHeaders()).add(signature);
    return signArrayBuilder.end().build().get(0);
  }

  public static Signature deserialize(byte[] signature) {
    return decode(CborUtils.decode(signature));
  }

  public static Signature decode(DataItem cborMessage) {
    try {
      List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
      if (messageArray.size() != 3) {
        throw new CoseException("Error while decoding Signature. Expected 3 items,"
            + "received " + messageArray.size());
      }
      return Signature.builder()
          .withProtectedHeaderBytes(CborUtils.asByteString(messageArray.get(0)).getBytes())
          .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
          .withSignature(CborUtils.asByteString(messageArray.get(2)).getBytes())
          .build();
    } catch (CborException ex) {
      throw new CoseException("Error while decoding Signature", ex);
    }
  }

  public byte[] getSignature() {
    return signature;
  }

  public static Builder builder() {
    return new Builder();
  }
}
