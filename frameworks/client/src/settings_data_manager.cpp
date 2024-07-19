/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "settings_data_manager.h"
 
#include "iam_logger.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri.h"

#define LOG_TAG "PIN_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
const std::string SETTING_COLUMN_KEYWORD = "KEYWORD";
const std::string SETTING_COLUMN_VALUE = "VALUE";
const char *PIN_SETTING_URI_PROXY = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_";
const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
} // namespace

SettingsDataManager::~SettingsDataManager()
{
    remoteObj_ = nullptr;
}

SettingsDataManager& SettingsDataManager::GetInstance()
{
    static SettingsDataManager settingsDataManager;
    settingsDataManager.Initialize();
    return settingsDataManager;
}

void SettingsDataManager::Initialize()
{
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("GetSystemAbilityManager return nullptr");
        return;
    }
    auto remoteObj = sam->GetSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_PINAUTH);
    if (remoteObj == nullptr) {
        IAM_LOGE("GetSystemAbility return nullptr");
        return;
    }
    remoteObj_ = remoteObj;
}

bool SettingsDataManager::GetIntValue(int32_t userId, const std::string& key, int32_t &value)
{
    std::string valueStr = "";
    if (!GetStringValue(userId, key, valueStr)) {
        IAM_LOGE("GetStringValue failed");
        return false;
    }
    const int32_t DECIMAL = 10;
    value = static_cast<int32_t>(strtoll(valueStr.c_str(), nullptr, DECIMAL));
    return true;
}

bool SettingsDataManager::GetStringValue(int32_t userId, const std::string& key, std::string& value)
{
    auto helper = CreateDataShareHelper(userId);
    if (helper == nullptr) {
        return false;
    }
    std::vector<std::string> columns = {SETTING_COLUMN_VALUE};
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_COLUMN_KEYWORD, key);
    Uri uri(AssembleUri(userId, key));
    auto resultSet = helper->Query(uri, predicates, columns);
    ReleaseDataShareHelper(helper);
    if (resultSet == nullptr) {
        IAM_LOGE("helper->Query return nullptr");
        return false;
    }
    int32_t count;
    resultSet->GetRowCount(count);
    if (count == 0) {
        IAM_LOGE("not found value, key=%{public}s, count=%{public}d", key.c_str(), count);
        resultSet->Close();
        return false;
    }
    const int32_t index = 0;
    resultSet->GoToRow(index);
    int32_t ret = resultSet->GetString(index, value);
    resultSet->Close();
    if (ret != DataShare::E_OK) {
        IAM_LOGE("resultSet->GetString return not ok, ret=%{public}d", ret);
        return false;
    }
    return true;
}

std::shared_ptr<DataShare::DataShareHelper> SettingsDataManager::CreateDataShareHelper(int32_t userId)
{
    std::string uriStr = std::string(PIN_SETTING_URI_PROXY) + std::to_string(userId) + "?Proxy=true";
    std::string extUriStr(SETTINGS_DATA_EXT_URI);
    auto helper = DataShare::DataShareHelper::Creator(remoteObj_, uriStr, extUriStr);
    if (helper == nullptr) {
        IAM_LOGE("helper is nullptr, uri=%{public}s", uriStr.c_str());
        return nullptr;
    }
    return helper;
}

bool SettingsDataManager::ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper>& helper)
{
    if (!helper->Release()) {
        IAM_LOGE("release helper fail");
        return false;
    }
    return true;
}

Uri SettingsDataManager::AssembleUri(int32_t userId, const std::string& key)
{
    std::string uriStr = std::string(PIN_SETTING_URI_PROXY) + std::to_string(userId) + "?Proxy=true";
    Uri uri(uriStr + "&key=" + key);
    return uri;
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS