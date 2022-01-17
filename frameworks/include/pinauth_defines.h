/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PINAUTH_DEFINES_H
#define PINAUTH_DEFINES_H

#include <vector>
#include <stdint.h>

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
enum AuthSubType {
/**
 * Authentication sub type six number pin.
 */
    PIN_SIX = 10000,
/**
 * Authentication sub type self defined number pin.
 */
    PIN_NUMBER = 10001,
/**
 * Authentication sub type 2D face.
 */
    PIN_MIXED = 10002,
/**
 * Authentication sub type 2D face.
 */
    FACE_2D = 20000,
/**
 * Authentication sub type 3D face.
 */
    FACE_3D = 20001
};

enum AUTH_SCHEDULE_COMMAND {
    COMMAND_ENROLL_PIN = 0,
    COMMAND_AUTH_PIN = 1,
    COMMAND_CANCEL_ENROLL = 2,
    COMMAND_CANCEL_AUTH = 3,
};

enum AUTH_PROPERTY_COMMAND {
    COMMAND_DELETE_PIN = 0,
    COMMAND_CHECK_PIN = 1,
};

enum ResultCode {
/**
 * Indicates that authentication is success or ability is supported.
 */
    SUCCESS = 0,
/**
 * Indicates the authenticator fails to identify user.
 */
    FAIL = 1,
/**
 * Indicates other errors.
 */
    GENERAL_ERROR = 2,
/**
 * Indicates that authentication has been canceled.
 */
    CANCELED = 3,
/**
 * Indicates that authentication has timed out.
 */
    TIMEOUT = 4,
/**
 * Indicates that this authentication type is not supported.
 */
    TYPE_NOT_SUPPORT = 5,
/**
 * Indicates that the authentication trust level is not supported.
 */
    TRUST_LEVEL_NOT_SUPPORT = 6,
/**
 * Indicates that the authentication task is busy. Wait for a few seconds and try again.
 */
    BUSY = 7,
/**
 * Indicates incorrect parameters.
 */
    INVALID_PARAMETERS = 8,
/**
 * Indicates that the authenticator is locked.
 */
    LOCKED = 9,
/**
 * Indicates that the user has not enrolled the authenticator.
 */
    NOT_ENROLLED = 10
};
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
#endif