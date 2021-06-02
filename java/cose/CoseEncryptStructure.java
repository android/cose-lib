/*
 * Copyright 2020 Google LLC
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

package cose;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;

/**
 * A CBOR Object Signing and Encryption (COSE) encrypt structure which is used as the Additional
 * Authenticated Data (AAD) during encryption operations, as defined in go/rfc/8152#section-5.3.
 */
public final class CoseEncryptStructure {

  public static byte[] buildEncryptStructure(
      Context context, byte[] protectedAttributes, byte[] externalAad) {
    DataItem coseEncryptedStructure =
        new CborBuilder()
            .addArray()
            .add(context.toString())
            .add(protectedAttributes)
            .add(externalAad)
            .end()
            .build()
            .get(0);
    return CborUtil.encode(coseEncryptedStructure);
  }

  /** A text string identifying the context of the authenticated data structure. */
  public enum Context {
    // Encrypt0 for the content encryption of a COSE_Encrypt0 data structure.
    ENCRYPT_0,
    // Encrypt for the first layer of a COSE_Encrypt data structure (i.e., for content encryption).
    ENCRYPT,
    // Enc_Recipient for a recipient encoding to be placed in an COSE_Encrypt data structure.
    ENC_RECIPIENT,
    // Mac_Recipient for a recipient encoding to be placed in a MACed message structure.
    MAC_RECIPIENT,
    // Rec_Recipient for a recipient encoding to be placed in a recipient structure.
    REC_RECIPIENT,
  }

  private CoseEncryptStructure() {}
}
