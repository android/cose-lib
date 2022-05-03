package com.google.cose.utils;

import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.UnsignedInteger;

/**
 * Algorithms to be used by cose library.
 * This enum helps in maintaining correct mac/signature/cipher instances in JCA.
 */
public enum Algorithm {
  SIGNING_ALGORITHM_ECDSA_SHA_256(-7, "SHA256withECDSA"),
  SIGNING_ALGORITHM_ECDSA_SHA_384(-35, "SHA384withECDSA"),
  SIGNING_ALGORITHM_ECDSA_SHA_512(-36, "SHA512withECDSA"),
  SIGNING_ALGORITHM_EdDSA(-8, "NonewithEdDSA"),
  MAC_ALGORITHM_HMAC_SHA_256_64(4, "HmacSHA256"),
  MAC_ALGORITHM_HMAC_SHA_256_256(5, "HmacSHA256"),
  MAC_ALGORITHM_HMAC_SHA_384_384(6, "HmacSHA384"),
  MAC_ALGORITHM_HMAC_SHA_512_512(7, "HmacSHA512"),

  ENCRYPTION_AES_128_GCM(1, "AES"),
  ENCRYPTION_AES_192_GCM(2, "AES"),
  ENCRYPTION_AES_256_GCM(3, "AES"),

  DIRECT_CEK_USAGE(-6, null);

  private final int algorithmId;
  private final String instance;

  Algorithm(int algorithmId, String instance) {
    this.algorithmId = algorithmId;
    this.instance = instance;
  }

  public String getInstance() {
    return instance;
  }

  public Number getAlgorithmId() {
    if (algorithmId < 0) {
      return new NegativeInteger(algorithmId);
    }
    return new UnsignedInteger(algorithmId);
  }
}
