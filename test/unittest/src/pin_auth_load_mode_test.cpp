/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "pin_auth_load_mode_test.h"

#include "iam_common_defines.h"
#include "system_param_manager.h"
#include "load_mode_handler_default.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void PinAuthLoadModeTest::SetUpTestCase()
{
}

void PinAuthLoadModeTest::TearDownTestCase()
{
}

void PinAuthLoadModeTest::SetUp()
{
}

void PinAuthLoadModeTest::TearDown()
{
}

HWTEST_F(PinAuthLoadModeTest, SystemParamManagerTest001, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam("useriam.pinAuthLoadModeTestParam001", "true");
    EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam001",""), "true");

    SystemParamManager::GetInstance().SetParam("useriam.pinAuthLoadModeTestParam002", "true");
    SystemParamManager::GetInstance().SetParam("useriam.pinAuthLoadModeTestParam002", "true");
}

HWTEST_F(PinAuthLoadModeTest, SystemParamManagerTest002, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParamTwice("useriam.pinAuthLoadModeTestParam003", "true", "true");
    EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam003",""), "true");

    SystemParamManager::GetInstance().SetParamTwice("useriam.pinAuthLoadModeTestParam004", "true", "false");
    EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam004",""), "false");

    SystemParamManager::GetInstance().SetParam("useriam.pinAuthLoadModeTestParam005", "true");
    SystemParamManager::GetInstance().SetParamTwice("useriam.pinAuthLoadModeTestParam005", "true", "false");
    EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam005",""), "false");

    SystemParamManager::GetInstance().SetParam("useriam.pinAuthLoadModeTestParam006", "true");
    SystemParamManager::GetInstance().SetParamTwice("useriam.pinAuthLoadModeTestParam006", "true", "true");
    EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam006",""), "true");
}

HWTEST_F(PinAuthLoadModeTest, SystemParamManagerTest003, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam("useriam.pinAuthLoadModeTestParam007", "true");
    EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam007",""), "true");

    SystemParamManager::GetInstance().WatchParam("useriam.pinAuthLoadModeTestParam007", [](const std::string &value) {
        if (value == "true"){
            EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam007",""), "true");
        }
    });
    
    SystemParamManager::GetInstance().SetParam("useriam.pinAuthLoadModeTestParam007", "true");
}

HWTEST_F(PinAuthLoadModeTest, SystemParamManagerTest004, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam("useriam.pinAuthLoadModeTestParam008", "true");
    EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam008",""), "true");

    SystemParamManager::GetInstance().WatchParam("useriam.pinAuthLoadModeTestParam008", [](const std::string &value) {
        if (value == "true"){
            EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam008",""), "true");
        }
    });

    SystemParamManager::GetInstance().WatchParam("useriam.pinAuthLoadModeTestParam008", [](const std::string &value) {
        if (value == "true"){
            EXPECT_EQ(SystemParamManager::GetInstance().GetParam("useriam.pinAuthLoadModeTestParam008",""), "true");
        }
    });

    SystemParamManager::GetInstance().SetParam("useriam.pinAuthLoadModeTestParam008", "true");
}

HWTEST_F(PinAuthLoadModeTest, LoadModeHandlerDefaultTest001, TestSize.Level0)
{
    SystemParamManager::GetInstance().SetParam("bootevent.useriam.fwkready", "true");
    LoadModeHandlerDefault::GetInstance().OnFrameworkDown();
    EXPECT_EQ(SystemParamManager::GetInstance().GetParam("bootevent.useriam.fwkready",""), "false");
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
