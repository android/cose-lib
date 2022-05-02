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
 * Implements COSE_Sign1 message structure.
 */
public class Sign1Message extends CoseMessage {
  private final byte[] message;
  private final byte[] signature;

  Sign1Message(byte[] protectedHeaderBytes, Map unprotectedHeaders, byte[] message, byte[] sign) {
    super(protectedHeaderBytes, unprotectedHeaders);
    this.message = message;
    this.signature = sign;
  }

  static class Builder {
    private byte[] protectedHeaderBytes;
    private Map unprotectedHeaders;
    private byte[] message;
    private byte[] signature;
    public Sign1Message build() {
      if ((protectedHeaderBytes != null) && (unprotectedHeaders != null) && (message != null)
          && (signature != null)) {
        return new Sign1Message(protectedHeaderBytes, unprotectedHeaders, message, signature);
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

    public Builder withMessage(byte[] message) {
      this.message = message;
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
    signArrayBuilder.add(getProtectedHeaderBytes()).add(getUnprotectedHeaders()).add(message)
        .add(signature);
    return signArrayBuilder.end().build().get(0);
  }

  public static Sign1Message deserialize(byte[] messageBytes) {
    return decode(CborUtils.decode(messageBytes));
  }

  public static Sign1Message decode(DataItem cborMessage) {
    try {
      List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
      if (messageArray.size() != 4) {
        throw new CoseException("Error while decoding Sign1Message. Expected 4 items,"
            + "received " + messageArray.size());
      }
      return Sign1Message.builder()
          .withProtectedHeaderBytes(CborUtils.asByteString(messageArray.get(0)).getBytes())
          .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
          .withMessage(CborUtils.asByteString(messageArray.get(2)).getBytes())
          .withSignature(CborUtils.asByteString(messageArray.get(3)).getBytes())
          .build();
    } catch (CborException ex) {
      throw new CoseException("Error while decoding Sign1Message", ex);
    }
  }

  public byte[] getMessage() {
    return message;
  }

  public byte[] getSignature() {
    return signature;
  }

  public static Builder builder() {
    return new Builder();
  }
}
