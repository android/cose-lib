package com.google.cose;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.exceptions.CoseException;
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

  public abstract DataItem encode() throws CoseException;

  public byte[] serialize() throws CborException, CoseException {
    return CborUtils.encode(encode());
  }

  public byte[] getProtectedHeaderBytes() {
    return protectedHeaderBytes;
  }

  public Map getProtectedHeaders() throws CoseException, CborException {
    if (protectedHeaderBytes.length == 0) {
      return new Map();
    } else {
      return CborUtils.asMap(CborUtils.decode(protectedHeaderBytes));
    }
  }

  public Map getUnprotectedHeaders() {
    return unprotectedHeaders;
  }
}
