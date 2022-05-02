package com.google.cose.structures;

import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.utils.CborUtils;

/**
 * Encodes the Sig_Structure as mentioned in COSE RFC section 4.4
 */
public class SignStructure {
  private final String context;
  private final Map protectedBodyHeaders;
  private final Map protectedSignHeaders;
  private final byte[] externalAad;
  private final byte[] message;

  public SignStructure(String context, Map bodyHeaders, Map signHeaders, byte[] externalAad,
      byte[] message) {
    this.context = context;
    this.protectedBodyHeaders = bodyHeaders;
    this.protectedSignHeaders = signHeaders;
    this.externalAad = externalAad;
    this.message = message;
  }

  public byte[] serialize() {
    return CborUtils.encode(encode());
  }

  public DataItem encode() {
    return CborUtils.encodeStructure(context, protectedBodyHeaders, protectedSignHeaders,
        externalAad, message);
  }
}
