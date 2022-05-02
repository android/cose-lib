package com.google.cose.structures;

import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.utils.CborUtils;

/**
 * Encodes the MAC_Structure as mentioned in COSE RFC section 6.3
 */
public class MacStructure {
  private final String context;
  private final Map protectedHeaders;
  private final byte[] externalAad;
  private final byte[] message;

  public MacStructure(String context, Map headers, byte[] externalAad, byte[] message) {
    this.context = context;
    this.protectedHeaders = headers;
    this.externalAad = externalAad;
    this.message = message;
  }

  public byte[] serialize() {
    return CborUtils.encode(encode());
  }

  public DataItem encode() {
    return CborUtils.encodeStructure(context, protectedHeaders, null, externalAad, message);
  }
}
