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

#include "pin_auth_register_test.h"

#include "file_ex.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "iam_ptr.h"
#include "mock_inputer.h"
#include "pinauth_register.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

static uint64_t tokenId;

void PinAuthRegisterTest::SetUpTestCase()
{
    static const char *PERMS[] = {
        "ohos.permission.ACCESS_PIN_AUTH"
    };
    string isEnforcing;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = PERMS,
        .acls = nullptr,
        .processName = "pin_auth_service_test",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    LoadStringFromFile("/sys/fs/selinux/enforce", isEnforcing);
    if (isEnforcing.compare("1") == 0) {
        PinAuthRegisterTest::isEnforcing_ = true;
        SaveStringToFile("/sys/fs/selinux/enforce", "0");
    }
}

void PinAuthRegisterTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    if (PinAuthRegisterTest::isEnforcing_) {
        SaveStringToFile("/sys/fs/selinux/enforce", "1");
    }
}

void PinAuthRegisterTest::SetUp()
{
}

void PinAuthRegisterTest::TearDown()
{
}

bool PinAuthRegisterTest::isEnforcing_ = false;

HWTEST_F(PinAuthRegisterTest, PinAuthRegisterTest001, TestSize.Level0)
{
    std::shared_ptr<IInputer> testInputer = nullptr;
    EXPECT_EQ(PinAuthRegister::GetInstance().RegisterInputer(testInputer), false);
    PinAuthRegister::GetInstance().UnRegisterInputer();
}

HWTEST_F(PinAuthRegisterTest, PinAuthRegisterTest002, TestSize.Level0)
{
    std::shared_ptr<IInputer> testInputer = Common::MakeShared<MockInputer>();
    EXPECT_NE(testInputer, nullptr);
    EXPECT_EQ(PinAuthRegister::GetInstance().RegisterInputer(testInputer), false);
    PinAuthRegister::GetInstance().UnRegisterInputer();
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
