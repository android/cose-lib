/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.cose;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.cose.exceptions.CoseException;
import com.google.cose.structure.EncryptStructure;
import com.google.cose.structure.EncryptStructure.EncryptionContext;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.CoseUtils;
import com.google.cose.utils.Headers;
import java.util.List;

/**
 * Implements COSE_Encrypt0 message.
 */
public class Encrypt0Message extends CoseMessage {
  byte[] ciphertext;

  private Encrypt0Message(Map protectedHeaders, Map unprotectedHeaders, byte[] ciphertext) {
    super(protectedHeaders, unprotectedHeaders);
    this.ciphertext = ciphertext;
  }

  public static class Builder {
    private Map protectedHeaders;
    private Map unprotectedHeaders;
    private byte[] ciphertext;
    public Encrypt0Message build() throws CoseException {
      if ((protectedHeaders != null) && (unprotectedHeaders != null)) {
        return new Encrypt0Message(protectedHeaders, unprotectedHeaders, ciphertext);
      } else {
        throw new CoseException("Some fields are missing.");
      }
    }

    public Builder withProtectedHeaders(Map protectedHeaders) {
      this.protectedHeaders = protectedHeaders;
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

    /**
     * Takes in key and message with other parameters to generate Ciphertext to be used in message.
     * @param key EncryptionKey object
     * @param message message to be encrypted
     * @param iv iv to be used for encryption
     * @param externalAad external aad to be used with encryption
     * @param algorithm algorithm for encryption.
     * @return Encrypt0Message.Builder object
     * @throws CborException if cbor information was not parseable
     * @throws CoseException if encryption fails for some reason
     */
    public Builder generateCiphertext(EncryptionKey key, byte[] message, byte[] iv,
        byte[] externalAad, Algorithm algorithm) throws CborException, CoseException {
      this.ciphertext = key.encrypt(algorithm, message, iv, new EncryptStructure(
          EncryptionContext.ENCRYPT0, protectedHeaders, externalAad).serialize());
      return this;
    }
  }

  @Override
  public DataItem encode() throws CborException {
    ArrayBuilder<CborBuilder> encryptArrayBuilder = new CborBuilder().addArray();
    encryptArrayBuilder
        .add(CoseUtils.serializeProtectedHeaders(getProtectedHeaders()))
        .add(getUnprotectedHeaders())
        .add(getCiphertext());
    return encryptArrayBuilder.end().build().get(0);
  }

  public static Encrypt0Message deserialize(byte[] messageBytes) throws CborException, CoseException {
    return decode(CborUtils.decode(messageBytes));
  }

  public static Encrypt0Message decode(DataItem cborMessage) throws CborException, CoseException {
    List<DataItem> messageArray = CborUtils.asArray(cborMessage).getDataItems();
    if (messageArray.size() != 3) {
      throw new CoseException("Error while decoding Encrypt0Message. Expected 3 items,"
          + "received " + messageArray.size());
    }
    return Encrypt0Message.builder()
        .withProtectedHeaders(CoseUtils.asProtectedHeadersMap(messageArray.get(0)))
        .withUnprotectedHeaders(CborUtils.asMap(messageArray.get(1)))
        .withCiphertext(CoseUtils.getBytesFromBstrOrNilValue(messageArray.get(2)))
        .build();
  }

  public byte[] getCiphertext() {
    return ciphertext;
  }

  public static Builder builder() {
    return new Builder();
  }

  public byte[] decrypt(EncryptionKey key, byte[] detachedCiphertextContent, byte[] externalAad,
      Algorithm algorithm) throws CborException, CoseException {
    byte[] ciphertext = this.ciphertext;
    if (ciphertext == null) {
      ciphertext = detachedCiphertextContent;
    }

    // find algorithm in the unprotected headers if provided with null.
    if (algorithm == null) {
      algorithm = Algorithm.fromCoseAlgorithmId(
          CborUtils.asInteger(findAttributeInHeaders(Headers.MESSAGE_HEADER_ALGORITHM))
      );
    }

    byte[] iv = CborUtils.asByteString(findAttributeInHeaders(Headers.MESSAGE_HEADER_BASE_IV))
        .getBytes();
    // generate aad out of the external aad.
    byte[] aad = new EncryptStructure(EncryptionContext.ENCRYPT0, getProtectedHeaders(), externalAad)
        .serialize();
    return key.decrypt(algorithm, ciphertext, iv, aad);
  }
}
