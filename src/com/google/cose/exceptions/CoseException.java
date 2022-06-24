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

package com.google.cose.exceptions;

/**
 * This class is used for throwing any exceptions that may occur during parsing and serialization of
 * byte data into their respective COSE components.
 */
public class CoseException extends Exception {
  public static final String MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE = "Missing key material "
      + "information. Need either public or private key bytes.";
  public static final String UNSUPPORTED_CURVE_EXCEPTION_MESSAGE = "Unsupported Curve provided.";

  public CoseException(final String message) {
    super(message);
  }

  public CoseException(final String message, final Throwable ex) {
    super(message, ex);
  }
}
