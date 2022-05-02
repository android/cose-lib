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
 * Implements COSE_Mac message structure.
 */
public class Mac0Message extends CoseMessage {
  private final byte[] message;
  private final byte[] tag;

  Mac0Message(byte[] protectedHeaderBytes, Map unprotectedHeaders, byte[] message, byte[] tag) {
    super(protectedHeaderBytes, unprotectedHeaders);
    this.message = message;
    this.tag = tag;
  }

  static class Builder {
    private byte[] protectedHeaderBytes;
    private Map unprotectedHeaders;
    private byte[] message;
    private byte[] tag;
    public Mac0Message build() {
      if ((protectedHeaderBytes != null) && (unprotectedHeaders != null) && (message != null)
          && (tag != null)) {
        return new Mac0Message(protectedHeaderBytes, unprotectedHeaders, message, tag);
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

    public Builder withTag(byte[] tag) {
      this.tag = tag;
      return this;
    }
  }

  @Override
  public DataItem encode() {
    ArrayBuilder<CborBuilder> macArrayBuilder = new CborBuilder().addArray();
    macArrayBuilder.add(getProtectedHeaderBytes()).add(getUnprotectedHeaders()).add(message)
        .add(tag);
    return macArrayBuilder.end().build().get(0);
  }

  public static Mac0Message deserialize(byte[] messageBytes) {
    return decode(CborUtils.decode(messageBytes));
  }

  public static Mac0Message decode(DataItem cborMessage) {
    try {
      List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
      if (messageArray.size() != 4) {
        throw new CoseException("Error while decoding Mac0Message. Expected 4 items,"
            + "received " + messageArray.size());
      }
      return Mac0Message.builder()
          .withProtectedHeaderBytes(CborUtils.asByteString(messageArray.get(0)).getBytes())
          .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
          .withMessage(CborUtils.asByteString(messageArray.get(2)).getBytes())
          .withTag(CborUtils.asByteString(messageArray.get(3)).getBytes())
          .build();
    } catch (CborException ex) {
      throw new CoseException("Error while decoding Mac0Message", ex);
    }
  }

  public byte[] getMessage() {
    return message;
  }

  public byte[] getTag() {
    return tag;
  }

  public static Builder builder() {
    return new Builder();
  }
}
