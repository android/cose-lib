package com.google.cose.structures;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.utils.CborUtils;

/**
 * Encodes the Enc_Structure as mentioned in COSE RFC section 5.3
 */
public class EncryptStructure {
  private final String context;
  private final Map protectedHeaders;
  private final byte[] externalAad;

  public EncryptStructure(String context, Map headers, byte[] externalAad) {
    this.context = context;
    this.protectedHeaders = headers;
    this.externalAad = externalAad;
  }

  public byte[] serialize() {
    return CborUtils.encode(encode());
  }

  public DataItem encode() {
    return CborUtils.encodeStructure(context, protectedHeaders, null, externalAad, null);
  }
}
