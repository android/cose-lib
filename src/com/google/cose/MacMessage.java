package com.google.cose;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.CborUtils;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Implements COSE_Mac message structure.
 */
public class MacMessage extends CoseMessage {
  protected List<Recipient> recipients;
  private final byte[] message;
  private final byte[] tag;

  MacMessage(byte[] protectedHeaderBytes, Map unprotectedHeaders, byte[] message, byte[] tag,
      List<Recipient> recipients) {
    super(protectedHeaderBytes, unprotectedHeaders);
    this.message = message;
    this.tag = tag;
    this.recipients = recipients;
  }

  static class Builder {
    private byte[] protectedHeaderBytes;
    private Map unprotectedHeaders;
    private byte[] message;
    private byte[] tag;
    private List<Recipient> recipients;

    public MacMessage build() {
      if ((protectedHeaderBytes != null) && (unprotectedHeaders != null) && (message != null)
          && (tag != null) && (recipients != null)) {
        return new MacMessage(protectedHeaderBytes, unprotectedHeaders, message, tag, recipients);
      } else {
        throw new CoseException("Some fields are missing.");
      }
    }

    public Builder withProtectedHeaderBytes(byte[] protectedHeaderBytes) {
      this.protectedHeaderBytes = protectedHeaderBytes;
      return this;
    }

    public Builder withProtectedHeaders(Map protectedHeaders) {
      if (protectedHeaderBytes != null) {
        throw new CoseException("Cannot use both withProtectedHeaderBytes and withProtectedHeaders");
      }
      if (protectedHeaders == null || protectedHeaders.getKeys().size() == 0) {
        this.protectedHeaderBytes = new byte[0];
      } else {
        this.protectedHeaderBytes = CborUtils.encode(protectedHeaders);
      }
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

    public Builder withRecipients(List<Recipient> recipients) {
      this.recipients = recipients;
      return this;
    }
  }

  @Override
  public DataItem encode() {
    ArrayBuilder<CborBuilder> macArrayBuilder = new CborBuilder().addArray();
    macArrayBuilder.add(getProtectedHeaderBytes()).add(getUnprotectedHeaders()).add(message)
        .add(tag);
    ArrayBuilder<ArrayBuilder<CborBuilder>> recipientArrayBuilder = macArrayBuilder.addArray();

    if (recipients == null) {
      throw new CoseException("Error while serializing MacMessage. Recipient field not found.");
    }

    for (Recipient recipient : recipients) {
      recipientArrayBuilder.add(recipient.encode());
    }
    recipientArrayBuilder.end();

    return macArrayBuilder.end().build().get(0);
  }

  public static MacMessage deserialize(byte[] messageBytes) {
    return decode(CborUtils.decode(messageBytes));
  }

  public static MacMessage decode(DataItem cborMessage) {
    try {
      List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
      if (messageArray.size() != 5) {
        throw new CoseException("Error while decoding MacMessage. Expected 5 items,"
            + "received " + messageArray.size());
      }
      List<DataItem> recipients = CborUtils.asArray(messageArray.get(4)).getDataItems();

      return MacMessage.builder()
          .withProtectedHeaderBytes(CborUtils.asByteString(messageArray.get(0)).getBytes())
          .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
          .withMessage(CborUtils.asByteString(messageArray.get(2)).getBytes())
          .withTag(CborUtils.asByteString(messageArray.get(3)).getBytes())
          .withRecipients(recipients.stream().map(Recipient::decode).collect(Collectors.toList()))
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
