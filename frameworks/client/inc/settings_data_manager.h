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

#ifndef SETTINGS_DATA_MANAGER_H
#define SETTINGS_DATA_MANAGER_H

#include "datashare_helper.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class SettingsDataManager : public NoCopyable {
public:
    SettingsDataManager() = default;
    ~SettingsDataManager() override = default;
    static bool GetIntValue(int32_t userId, const std::string &key, int32_t &value);

private:
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t userId);
    void ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> &helper);
    Uri AssembleUri(int32_t userId, const std::string &key);
    bool GetStringValue(int32_t userId, const std::string &key, std::string &value);
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // SETTINGS_DATA_MANAGER_H
