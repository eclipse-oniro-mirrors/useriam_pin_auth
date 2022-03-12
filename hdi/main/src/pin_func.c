/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "pin_func.h"
#include "adaptor_algorithm.h"
#include "buffer.h"
#include "securec.h"

static KeyPair *g_keyPair = NULL;

ResultCode DoEnrollPin(PinEnrollParam *pinEnrollParam, Buffer *retTlv)
{
    if (pinEnrollParam == NULL || !IsBufferValid(retTlv)) {
        LOG_ERROR("get invalid params.");
        return RESULT_BAD_PARAM;
    }
    uint64_t templateId = INVALID_TEMPLATE_ID;
    ResultCode ret = AddPin(pinEnrollParam, &templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("AddPin fail.");
        return ret;
    }

    ret = GenerateRetTlv(RESULT_SUCCESS, pinEnrollParam->scheduleId, pinEnrollParam->subType, templateId, retTlv);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GenerateRetTlv DoEnrollPin fail.");
    }

    return ret;
}

static ResultCode GetSubTypeAndFreezeTime(uint64_t *subType, int64_t templateId, uint64_t *freezeTime, uint32_t *conut)
{
    ResultCode ret = GetSubType(templateId, subType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetSubType fail.");
        return ret;
    }
    uint64_t startFreezeTime = INIT_START_FREEZE_TIMES;
    ret = GetAntiBruteInfo(templateId, conut, &startFreezeTime);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetAntiBruteInfo fail.");
        return ret;
    }

    ret = ComputeFreezeTime(templateId, freezeTime, *conut, startFreezeTime);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ComputeFreezeTime fail.");
        return ret;
    }
    return RESULT_SUCCESS;
}

ResultCode DoAuthPin(PinAuthParam *pinAuthParam, Buffer *retTlv)
{
    if (!IsBufferValid(retTlv) || pinAuthParam == NULL) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }

    uint64_t subType = 0;
    uint64_t freezeTime = 0;
    uint32_t authErrorConut = INIT_AUTH_ERROR_COUNT;
    ResultCode ret = GetSubTypeAndFreezeTime(&subType, pinAuthParam->templateId, &freezeTime, &authErrorConut);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetSubTypeAndFreezeTime fail.");
        return ret;
    }

    if (freezeTime == 0) {
        ret = AuthPinById(&(pinAuthParam->pinData[0]), CONST_PIN_DATA_LEN, pinAuthParam->templateId);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("AuthPinById fail.");
        }
    } else {
        LOG_ERROR("Pin is freezing.");
        ret = RESULT_PIN_FREEZE;
    }

    ResultCode tlvRet = GenerateRetTlv(ret, pinAuthParam->scheduleId, subType, pinAuthParam->templateId, retTlv);
    if (tlvRet != RESULT_SUCCESS) {
        LOG_ERROR("GenerateRetTlv DoAuthPin fail.");
        return tlvRet;
    }
    return ret;
}

ResultCode DoQueryPinInfo(uint64_t templateId, PinCredentialInfos *pinCredentialInfo)
{
    if (pinCredentialInfo == NULL || templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("check DoQueryPin param fail!");
        return RESULT_BAD_PARAM;
    }
    uint32_t authErrorConut = INIT_AUTH_ERROR_COUNT;
    ResultCode ret = GetSubTypeAndFreezeTime(&(pinCredentialInfo->subType), templateId,
        &(pinCredentialInfo->freezeTime), &authErrorConut);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetSubTypeAndFreezeTime fail.");
        return ret;
    }
    if (pinCredentialInfo->freezeTime > 0) {
        pinCredentialInfo->remainTimes = 0;
    } else {
        ret = GetRemainTimes(templateId, &(pinCredentialInfo->remainTimes), authErrorConut);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("GetRemainTimes fail.");
            return ret;
        }
    }
    return ret;
}

ResultCode DoDeleteTemplate(uint64_t templateId)
{
    ResultCode ret = DelPinById(templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("delete pin fail.");
        return RESULT_BAD_DEL;
    }
    return RESULT_SUCCESS;
}

ResultCode GenerateKeyPair()
{
    DestoryKeyPair(g_keyPair);
    g_keyPair = GenerateEd25519KeyPair();
    if (g_keyPair == NULL) {
        LOG_ERROR("GenerateEd25519Keypair fail!");
        return RESULT_GENERAL_ERROR;
    }
    LOG_INFO("GenerateKeyPair success");
    return RESULT_SUCCESS;
}

ResultCode DoGetExecutorInfo(PinExecutorInfo *pinExecutorInfo)
{
    if (pinExecutorInfo == NULL) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    if (!IsEd25519KeyPairValid(g_keyPair)) {
        LOG_ERROR("key pair not init!");
        return RESULT_NEED_INIT;
    }
    uint32_t pubKeyLen = CONST_PUB_KEY_LEN;
    if (GetBufferData(g_keyPair->pubKey, pinExecutorInfo->pubKey, &pubKeyLen) != RESULT_SUCCESS) {
        LOG_ERROR("GetBufferData fail!");
        return RESULT_UNKNOWN;
    }
    pinExecutorInfo->esl = PIN_EXECUTOR_SECURITY_LEVEL;
    pinExecutorInfo->authAbility = PIN_AUTH_AIBNILITY;
    return RESULT_SUCCESS;
}

static ResultCode WriteTlvHead(const AuthAttributeType type, const uint32_t length, Buffer *buf)
{
    int32_t tempType = type;
    if (memcpy_s(buf->buf + buf->contentSize, buf->maxSize - buf->contentSize, &tempType, sizeof(tempType)) != EOK) {
        LOG_ERROR("copy type fail.");
        return RESULT_BAD_COPY;
    }
    buf->contentSize += sizeof(tempType);
    if (memcpy_s(buf->buf + buf->contentSize, buf->maxSize - buf->contentSize, &length, sizeof(length)) != EOK) {
        LOG_ERROR("copy length fail.");
        return RESULT_BAD_COPY;
    }
    buf->contentSize += sizeof(length);
    return RESULT_SUCCESS;
}

static ResultCode WriteTlv(const AuthAttributeType type, const uint32_t length, const uint8_t *value, Buffer *buf)
{
    if (WriteTlvHead(type, length, buf) != RESULT_SUCCESS) {
        LOG_ERROR("copy head fail.");
        return RESULT_BAD_COPY;
    }
    if (memcpy_s(buf->buf + buf->contentSize, buf->maxSize - buf->contentSize, value, length) != EOK) {
        LOG_ERROR("copy value fail.");
        return RESULT_BAD_COPY;
    }
    buf->contentSize += length;
    return RESULT_SUCCESS;
}

static Buffer *GetDataTlvContent(uint32_t result, uint64_t scheduleId, uint64_t subType, uint64_t templatedId)
{
    Buffer *ret = CreateBuffer(MAX_TLV_LEN);
    if (!IsBufferValid(ret)) {
        LOG_ERROR("no memory.");
        return NULL;
    }
    uint32_t acl = PIN_CAPABILITY_LEVEL;
    if (WriteTlv(AUTH_RESULT_CODE, sizeof(result), (const uint8_t *)&result, ret) != RESULT_SUCCESS ||
        WriteTlv(AUTH_TEMPLATE_ID, sizeof(templatedId), (const uint8_t *)&templatedId, ret) != RESULT_SUCCESS ||
        WriteTlv(AUTH_SESSION_ID, sizeof(scheduleId), (const uint8_t *)&scheduleId, ret) != RESULT_SUCCESS ||
        WriteTlv(AUTH_SUBTYPE, sizeof(subType), (const uint8_t *)&subType, ret) != RESULT_SUCCESS ||
        WriteTlv(AUTH_CAPABILITY_LEVEL, sizeof(acl), (const uint8_t *)&acl, ret) != RESULT_SUCCESS) {
        LOG_ERROR("write tlv fail.");
        DestoryBuffer(ret);
        return NULL;
    }
    return ret;
}

ResultCode GenerateRetTlv(uint32_t result, uint64_t scheduleId, uint64_t subType, uint64_t templatedId,
    Buffer *retTlv)
{
    if (!IsBufferValid(retTlv) || !IsEd25519KeyPairValid(g_keyPair)) {
        LOG_ERROR("param is invalid.");
        return RESULT_BAD_PARAM;
    }
    Buffer *dataContent = GetDataTlvContent(result, scheduleId, subType, templatedId);
    if (!IsBufferValid(dataContent)) {
        LOG_ERROR("get data content fail.");
        return RESULT_BAD_COPY;
    }
    Buffer *signContent = NULL;
    if (Ed25519Sign(g_keyPair, dataContent, &signContent) != RESULT_SUCCESS) {
        LOG_ERROR("sign data fail.");
        DestoryBuffer(dataContent);
        return RESULT_GENERAL_ERROR;
    }
    uint32_t rootLen = TAG_AND_LEN_BYTE + dataContent->contentSize + TAG_AND_LEN_BYTE + ED25519_FIX_SIGN_BUFFER_SIZE;
    if (WriteTlvHead(AUTH_ROOT, rootLen, retTlv) != RESULT_SUCCESS ||
        WriteTlv(AUTH_EXECUTOR_DATA, dataContent->contentSize, dataContent->buf, retTlv) != RESULT_SUCCESS ||
        WriteTlv(AUTH_SIGNATURE, signContent->contentSize, signContent->buf, retTlv) != RESULT_SUCCESS) {
        LOG_ERROR("write tlv fail.");
        DestoryBuffer(dataContent);
        DestoryBuffer(signContent);
        return RESULT_BAD_COPY;
    }
    DestoryBuffer(dataContent);
    DestoryBuffer(signContent);
    return RESULT_SUCCESS;
}

ResultCode DoVerifyTemplateData(const uint64_t *templateIdList, uint32_t templateIdListLen)
{
    if (templateIdListLen != 0 && templateIdList == NULL) {
        LOG_ERROR("templateIdList should be not null, when templateIdListLen is not zero");
        return RESULT_BAD_PARAM;
    }
    ResultCode ret = VerifyTemplateDataPin(templateIdList, templateIdListLen);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("Verify TemplateDataPin fail.");
        return ret;
    }
    return RESULT_SUCCESS;
}
