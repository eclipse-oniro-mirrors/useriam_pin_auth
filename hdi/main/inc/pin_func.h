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

#ifndef PINAUTHTA_FUNC_H
#define PINAUTHTA_FUNC_H

#include "pin_db.h"

#define TAG_AND_LEN_BYTE 8
#define TAG_ANG_LEN_T 12
#define TAG_AND_LEN_S 16
#define MAX_TLV_LEN 200
#define SIGN_DATA_LEN 64
#define PIN_RET_TYPE_LEN 8
#define PIN_RET_DATA_LEN 72
#define PIN_CAPABILITY_LEVEL 3
#define ED25519_FIX_PUBKEY_BUFFER_SIZE 32
#define ED25519_FIX_PRIKEY_BUFFER_SIZE 64
#define PIN_EXECUTOR_SECURITY_LEVEL 2
#define PIN_AUTH_AIBNILITY 7

typedef enum {
    /**
     * Root tag
     */
    AUTH_ROOT = 1000000,

    /**
     * Result code
     */
    AUTH_RESULT_CODE = 1000001,

    /**
     * Tag of signature data in TLV
     */
    AUTH_SIGNATURE = 1000002,

    /**
     * Tag of templateId data in TLV
     */
    AUTH_TEMPLATE_ID = 1000004,

    /**
     * Session id, required when decode in C
     */
    AUTH_SESSION_ID = 1000008,

    /**
     * Tag of executor's data
     */
    AUTH_EXECUTOR_DATA = 1000013,

    /**
     * Tag of auth subType
     */
    AUTH_SUBTYPE = 1000014,

    /**
     * Tag of capability level
     */
    AUTH_CAPABILITY_LEVEL = 1000015
} AuthAttributeType;

typedef struct {
    uint64_t scheduleId;
    uint64_t templateId;
    uint8_t pinData[CONST_PIN_DATA_LEN];
} PinAuthParam;

typedef struct {
    uint64_t subType;
    uint64_t templateId;
} QueryCredential;

typedef struct {
    uint64_t subType;
    uint32_t remainTimes;
    uint64_t freezeTime;
} PinCredentialInfos;

typedef struct {
    uint32_t esl;
    uint64_t authAbility;
    uint8_t pubKey[CONST_PUB_KEY_LEN];
} PinExecutorInfo;

ResultCode DoEnrollPin(PinEnrollParam *pinEnrollParam, Buffer *retTlv);
ResultCode DoAuthPin(PinAuthParam *pinAuthParam, Buffer *data);
ResultCode DoQueryPinInfo(uint64_t templateId, PinCredentialInfos *pinCredentialInfo);
ResultCode DoDeleteTemplate(uint64_t templateId);
ResultCode GenerateRetTlv(uint32_t result, uint64_t scheduleId, uint64_t subType, uint64_t templatedId, Buffer *retTlv);
ResultCode GenerateKeyPair();
ResultCode DoGetExecutorInfo(PinExecutorInfo *pinExecutorInfo);
ResultCode DoVerifyTemplateData(const uint64_t *templateIdList, uint32_t templateIdListLen);

#endif // PINAUTHTA_FUNC_H