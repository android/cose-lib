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
 * Implements COSE_Encrypt0 message.
 */
public class Encrypt0Message extends CoseMessage {
  byte[] ciphertext;

  private Encrypt0Message(byte[] protectedHeaderBytes, Map unprotectedHeaders, byte[] ciphertext) {
    super(protectedHeaderBytes, unprotectedHeaders);
    this.ciphertext = ciphertext;
  }

  static class Builder {
    private byte[] protectedHeaderBytes;
    private Map unprotectedHeaders;
    private byte[] ciphertext;
    public Encrypt0Message build() {
      if ((protectedHeaderBytes != null) && (unprotectedHeaders != null) && (ciphertext != null)) {
        return new Encrypt0Message(protectedHeaderBytes, unprotectedHeaders, ciphertext);
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

    public Builder withCiphertext(byte[] ciphertext) {
      this.ciphertext = ciphertext;
      return this;
    }
  }

  @Override
  public DataItem encode() {
    ArrayBuilder<CborBuilder> encryptArrayBuilder = new CborBuilder().addArray();
    encryptArrayBuilder
        .add(getProtectedHeaderBytes())
        .add(getUnprotectedHeaders())
        .add(getCiphertext());
    return encryptArrayBuilder.end().build().get(0);
  }

  public static Encrypt0Message deserialize(byte[] messageBytes) {
    return decode(CborUtils.decode(messageBytes));
  }

  public static Encrypt0Message decode(DataItem cborMessage) {
    try {
      List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
      if (messageArray.size() != 3) {
        throw new CoseException("Error while decoding Encrypt0Message. Expected 3 items,"
            + "received " + messageArray.size());
      }
      Encrypt0Message.Builder builder = new Encrypt0Message.Builder();
      builder.withProtectedHeaderBytes(CborUtils.asByteString(messageArray.get(0)).getBytes());
      builder.withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)));
      builder.withCiphertext(CborUtils.asByteString(messageArray.get(2)).getBytes());
      return builder.build();
    } catch (CborException ex) {
      throw new CoseException("Error while decoding Encrypt0Message", ex);
    }
  }

  public byte[] getCiphertext() {
    return ciphertext;
  }

  public static Builder builder() {
    return new Builder();
  }
}
