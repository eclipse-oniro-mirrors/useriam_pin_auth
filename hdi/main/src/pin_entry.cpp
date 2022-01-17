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


#include "pthread.h"
#include <vector>

extern "C" {
    #include "pin_entry.h"
    #include "adaptor_memory.h"
    #include "adaptor_log.h"
    #include "securec.h"
    #include "pin_func.h"
}

namespace OHOS {
namespace UserIAM {
namespace PinAuth {

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

PinAuth::PinAuth(){ }

int32_t PinAuth::Init()
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("Init() pthread_mutex_lock fail!");
        return RESULT_GENERAL_ERROR;
    }
    LOG_INFO("start InIt pinAuth.");
    InitPinDb();

    if (GenerateKeyPair() != RESULT_SUCCESS) {
        LOG_ERROR("Init() GenerateKeyPair fail!");
        return RESULT_GENERAL_ERROR;
    }

    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("Init() pthread_mutex_unlock fail!");
        return RESULT_GENERAL_ERROR;
    }
    LOG_INFO("InIt pinAuth succ");

    return RESULT_SUCCESS;
}

int32_t PinAuth::Close()
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("Close() pthread_mutex_lock fail!");
        return RESULT_GENERAL_ERROR;
    }

    LOG_INFO("start Close pinAuth");
    DestroyPinDb();

    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("Close() pthread_mutex_unlock fail!");
        return RESULT_GENERAL_ERROR;
    }
    LOG_INFO("Close pinAuth succ");

    return RESULT_SUCCESS;
}

static ResultCode InitPinEnrollParam(PinEnrollParam *pinEnrollParam, uint64_t scheduleId, uint64_t subType,
    std::vector<uint8_t> &salt, std::vector<uint8_t> &pinData)
{
    pinEnrollParam->scheduleId= scheduleId;
    pinEnrollParam->subType = subType;
    if (memcpy_s(&(pinEnrollParam->salt[0]), CONST_SALT_LEN, &salt[0], CONST_SALT_LEN) != EOK) {
        LOG_ERROR("mem copy salt to pinEnrollParam fail!");
        return RESULT_GENERAL_ERROR;
    }

    if (memcpy_s(&(pinEnrollParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN) != EOK) {
        LOG_ERROR("copy pinData to pinEnrollParam fail!");
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}

static ResultCode SetResultTlv(Buffer *retTlv, std::vector<uint8_t> &resultTlv)
{
    resultTlv.resize(retTlv->contentSize);
    if (memcpy_s(&resultTlv[0], retTlv->contentSize, retTlv->buf, retTlv->contentSize) != EOK) {
        LOG_ERROR("copy retTlv to resultTlv fail!");
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}

int32_t PinAuth::EnrollPin(uint64_t scheduleId, uint64_t subType, std::vector<uint8_t> &salt, std::vector<uint8_t> &pinData,
    std::vector<uint8_t> &resultTlv)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return RESULT_BAD_PARAM;
    }
    if (salt.size() != CONST_SALT_LEN || pinData.size() != CONST_PIN_DATA_LEN) {
        LOG_ERROR("get bad params!");
        return RESULT_BAD_PARAM;
    }

    PinEnrollParam *pinEnrollParam = (PinEnrollParam *)Malloc(sizeof(PinEnrollParam));
    if (pinEnrollParam == NULL) {
        LOG_ERROR("generate pinEnrollParam fail!");
        return RESULT_GENERAL_ERROR;
    }
    ResultCode result = InitPinEnrollParam(pinEnrollParam, scheduleId, subType, salt, pinData);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("InitPinEnrollParamfail!");
        Free(pinEnrollParam);
        return RESULT_GENERAL_ERROR;
    }

    Buffer *retTlv = CreateBuffer(RESULT_TLV_LEN);
    result = DoEnrollPin(pinEnrollParam, retTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoEnrollPin fail!");
        goto ERROR;
    }

    result = SetResultTlv(retTlv, resultTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetRsultTlv fail!");
        goto ERROR;
    }

ERROR:
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        return RESULT_GENERAL_ERROR;
    }
    DestoryBuffer(retTlv);
    Free(pinEnrollParam);
    return result;
}

int32_t PinAuth::GetSalt(uint64_t templateId, std::vector<uint8_t> &salt)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("GetSalt() pthread_mutex_lock fail!");
        return RESULT_BAD_PARAM;
    }

    salt.resize(CONST_SALT_LEN);
    if (salt.size() != CONST_SALT_LEN) {
        LOG_ERROR("GetSalt() salt resize fail!");
        return RESULT_UNKNOWN;
    }

    uint32_t satLen = CONST_SALT_LEN;
    ResultCode result = DoGetSalt(templateId, &salt[0], &satLen);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetSalt() DoGetSalt fail!");
        return result;
    }

    if (pthread_mutex_unlock(&g_mutex) != RESULT_SUCCESS) {
        LOG_ERROR("GetSalt() pthread_mutex_unlock fail!");
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}

int32_t PinAuth::AuthPin(uint64_t scheduleId, uint64_t templateId, std::vector<uint8_t> &pinData,
    std::vector<uint8_t> &resultTlv)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return RESULT_BAD_PARAM;
    }
    if (pinData.size() != CONST_PIN_DATA_LEN) {
        LOG_ERROR("bad pidData len!");
        return RESULT_BAD_PARAM;
    }

    PinAuthParam *pinAuthParam = (PinAuthParam *)Malloc(sizeof(PinAuthParam));
    if (pinAuthParam == NULL) {
        LOG_ERROR("malloc pinAuthParam fail!");
        return RESULT_GENERAL_ERROR;
    }
    pinAuthParam->scheduleId = scheduleId;
    pinAuthParam->templateId = templateId;
    if (memcpy_s(&(pinAuthParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], pinData.size()) != EOK) {
        LOG_ERROR("Pin mem copy pinData to pinAuthParam fail!");
        Free(pinAuthParam);
        return RESULT_GENERAL_ERROR;
        
    }
    Buffer *retTlv = CreateBuffer(RESULT_TLV_LEN);
    ResultCode result = DoAuthPin(pinAuthParam, retTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoAuthPin fail!");
        goto ERROR;
    }

    result = SetResultTlv(retTlv, resultTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetRsultTlv fail!");
        goto ERROR;
    }

ERROR:
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        return RESULT_GENERAL_ERROR;
    }
    DestoryBuffer(retTlv);
    Free(pinAuthParam);
    return result;
}

int32_t PinAuth::QueryPinInfo(uint64_t templateId, PinCredentialInfo &pinCredentialInfoRet)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return RESULT_BAD_PARAM;
    }

    PinCredentialInfos *pinCredentialInfosRet = (PinCredentialInfos *)Malloc(sizeof(PinCredentialInfos));
    if (pinCredentialInfosRet == NULL) {
        LOG_ERROR("malloc pinCredentialInfosRet fail!");
        return RESULT_GENERAL_ERROR;
    }

    ResultCode result = DoQueryPinInfo(templateId, pinCredentialInfosRet);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoQueryPinInfo fail!");
        goto ERROR;
    }

    pinCredentialInfoRet.subType = pinCredentialInfosRet->subType;
    pinCredentialInfoRet.remainTimes = pinCredentialInfosRet->remainTimes;
    pinCredentialInfoRet.freezingTime = pinCredentialInfosRet->freezeTime;

ERROR:
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }
    Free(pinCredentialInfosRet);
    return result;
}

int32_t PinAuth::DeleteTemplate(uint64_t templateId)
{
    LOG_ERROR("Del templateId = %{public}llu", templateId);
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return RESULT_BAD_PARAM;
    }

    ResultCode result = DoDeleteTemplate(templateId);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoDeleteTemplate fail!");
        return RESULT_GENERAL_ERROR;
    }

    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }

    return result;
}

int32_t PinAuth::GetExecutorInfo(std::vector<uint8_t> &pubKey, uint32_t &esl, uint64_t &authAbility)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return RESULT_BAD_PARAM;
    }

    PinExecutorInfo *pinExecutorInfo = (PinExecutorInfo *)Malloc(sizeof(PinExecutorInfo));
    if (pinExecutorInfo == NULL) {
        LOG_ERROR("malloc pinExecutorInfo fail!");
        return RESULT_GENERAL_ERROR;
    }

    ResultCode result = DoGetExecutorInfo(pinExecutorInfo);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoGetExecutorInfo fail!");
        goto ERROR;
    }

    esl = pinExecutorInfo->esl;
    authAbility = pinExecutorInfo->authAbility;
    pubKey.resize(CONST_PUB_KEY_LEN);
    if (memcpy_s(&pubKey[0], CONST_PUB_KEY_LEN, &(pinExecutorInfo->pubKey[0]), CONST_PUB_KEY_LEN) != EOK) {
        LOG_ERROR("copy pinExecutorInfo to pubKey fail!");
        result = RESULT_GENERAL_ERROR;
        goto ERROR;
    }

ERROR:
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }
    Free(pinExecutorInfo);
    return result;
}

int32_t PinAuth::VerifyTemplateData(std::vector<uint64_t> templateIdList)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return RESULT_BAD_PARAM;
    }

    int32_t templateIdListLen = templateIdList.size();
    ResultCode result = DoVerifyTemplateData(&templateIdList[0], templateIdListLen);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoVerifyTemplateData fail!");
    }

    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }

    return result;
}

} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS
