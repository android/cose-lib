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

package com.google.cose.utils;

/**
 * This class contains COSE IANA IDs that we are going to be using in COSE implementation.
 */
public class Headers {
  public static final int KEY_PARAMETER_KEY_TYPE = 1;
  public static final int KEY_PARAMETER_KEY_ID = 2;
  public static final int KEY_PARAMETER_ALGORITHM = 3;
  public static final int KEY_PARAMETER_OPERATIONS = 4;
  public static final int KEY_PARAMETER_BASE_IV = 5;

  public static final int KEY_TYPE_RESERVED = 0;
  public static final int KEY_TYPE_OKP = 1;
  public static final int KEY_TYPE_EC2 = 2;
  public static final int KEY_TYPE_SYMMETRIC = 4;

  public static final int KEY_OPERATIONS_SIGN = 1;
  public static final int KEY_OPERATIONS_VERIFY = 2;
  public static final int KEY_OPERATIONS_ENCRYPT = 3;
  public static final int KEY_OPERATIONS_DECRYPT = 4;
  public static final int KEY_OPERATIONS_WRAP_KEY = 5;
  public static final int KEY_OPERATIONS_UNWRAP_KEY = 6;
  public static final int KEY_OPERATIONS_DERIVE_KEY = 7;
  public static final int KEY_OPERATIONS_DERIVE_BITS = 8;
  public static final int KEY_OPERATIONS_MAC_CREATE = 9;
  public static final int KEY_OPERATIONS_MAC_VERIFY = 10;

  public static final int MESSAGE_HEADER_ALGORITHM = 1;
  public static final int MESSAGE_HEADER_CRITICALITY = 2;
  public static final int MESSAGE_HEADER_CONTENT_TYPE = 3;
  public static final int MESSAGE_HEADER_KEY_ID = 4;
  public static final int MESSAGE_HEADER_BASE_IV = 5;
  public static final int MESSAGE_HEADER_PARTIAL_IV = 6;
  public static final int MESSAGE_HEADER_COUNTER_SIGNATURE = 7;

  public static final int KEY_PARAMETER_CURVE = -1;
  public static final int KEY_PARAMETER_X = -2;
  public static final int KEY_PARAMETER_Y = -3;
  public static final int KEY_PARAMETER_D = -4;

  public static final int KEY_PARAMETER_K = -1;

  public static final int CURVE_EC2_P256 = 1;
  public static final int CURVE_EC2_P384 = 2;
  public static final int CURVE_EC2_P521 = 3;

  public static final int CURVE_OKP_X25519 = 4;
  public static final int CURVE_OKP_X448 = 5;
  public static final int CURVE_OKP_ED25519 = 6;
  public static final int CURVE_OKP_ED448 = 7;

  public static final int ECDH_EPHEMERAL_KEY = -1;
  public static final int ECDH_STATIC_KEY = -2;
  public static final int ECDH_STATIC_KEY_ID = -3;

  // Avoiding instantiation of the class
  private Headers() {}
}
