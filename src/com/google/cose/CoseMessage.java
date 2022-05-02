package com.google.cose;

import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.utils.CborUtils;

/**
 * Implements the base class for COSE Message structure to be implemented for other message types.
 */
public abstract class CoseMessage {
  private final byte[] protectedHeaderBytes;
  private final Map unprotectedHeaders;

  CoseMessage(byte[] protectedHeaderBytes, Map unprotectedHeaders) {
    this.protectedHeaderBytes = protectedHeaderBytes;
    this.unprotectedHeaders = unprotectedHeaders;
  }

  // TODO: Add counter signature support

  public byte[] serialize() {
    return CborUtils.encode(encode());
  }

  public abstract DataItem encode();

  public byte[] getProtectedHeaderBytes() {
    return protectedHeaderBytes;
  }

  public Map getUnprotectedHeaders() {
    return unprotectedHeaders;
  }
}
