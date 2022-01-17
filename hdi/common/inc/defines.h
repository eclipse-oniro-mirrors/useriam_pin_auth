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

#ifndef COMMON_DEFINES_H
#define COMMON_DEFINES_H

typedef enum ResultCode {
    RESULT_SUCCESS = 0x0,
    RESULT_GENERAL_ERROR = 0x1,
    RESULT_BAD_PARAM = 0x2,
    RESULT_BAD_COPY = 0x3,
    RESULT_NO_MEMORY = 0x4,
    RESULT_NEED_INIT = 0x5,
    RESULT_NOT_FOUND = 0x6,
    RESULT_REACH_LIMIT = 0x7,
    RESULT_DUPLICATE_CHECK_FAILED = 0x8,
    RESULT_BAD_READ = 0x9,
    RESULT_BAD_WRITE = 0xA,
    RESULT_BAD_DEL = 0xB,
    RESULT_UNKNOWN = 0xC,
    RESULT_BAD_MATCH = 0xD,
    RESULT_BAD_SIGN = 0xE,
    RESULT_BUSY = 0xF,
    RESULT_PIN_FREEZE = 0x11,
    RESULT_PIN_FAIL = 0X12,
} ResultCode;

typedef enum AuthType {
    DEFAULT_AUTH_TYPE = 0,
    PIN_AUTH = 1,
    FACE_AUTH = 2,
} AuthType;

typedef enum AuthSubType {
    DEFAULT_TYPE = 0,
} AuthSubType;

#define MAX_DULPLICATE_CHECK 100

#endif
