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

#include "pin_auth_service_test.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "iam_ptr.h"
#include "mock_inputer_get_data.h"
#include "pin_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void PinAuthServiceTest::setTokenId() {
    static const char *PERMS[] = {
        "ohos.permission.ACCESS_PIN_AUTH"
    };
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
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void PinAuthServiceTest::SetUpTestCase()
{
}

void PinAuthServiceTest::TearDownTestCase()
{
}

void PinAuthServiceTest::SetUp()
{
}

void PinAuthServiceTest::TearDown()
{
}

HWTEST_F(PinAuthServiceTest, RegisterInputerTest001, TestSize.Level0)
{
    auto service = Common::MakeShared<PinAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_EQ(service->RegisterInputer(nullptr), false);
}

HWTEST_F(PinAuthServiceTest, UnRegisterInputerTest001, TestSize.Level0)
{
    auto service = Common::MakeShared<PinAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_NO_THROW(service->UnRegisterInputer());
}

HWTEST_F(PinAuthServiceTest, OnStartTest001, TestSize.Level0)
{
    auto service = Common::MakeShared<PinAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_NO_THROW(service->OnStart());
    EXPECT_NO_THROW(service->OnStart());
}

HWTEST_F(PinAuthServiceTest, OnStopTest001, TestSize.Level0)
{
    auto service = Common::MakeShared<PinAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_NO_THROW(service->OnStop());
}

HWTEST_F(PinAuthServiceTest, PinAuthServiceTest001, TestSize.Level0)
{
    setTokenId();
    auto service = Common::MakeShared<PinAuthService>();
    EXPECT_NE(service, nullptr);
    sptr<InputerGetData> testInputerGetData(nullptr);
    EXPECT_EQ(service->RegisterInputer(testInputerGetData), false);
    service->UnRegisterInputer();
}

HWTEST_F(PinAuthServiceTest, PinAuthServiceTest002, TestSize.Level0)
{
    setTokenId();
    auto service = Common::MakeShared<PinAuthService>();
    EXPECT_NE(service, nullptr);
    sptr<InputerGetData> testInputerGetData(new (std::nothrow) MockInputerGetData());
    EXPECT_NE(testInputerGetData, nullptr);
    EXPECT_EQ(service->RegisterInputer(testInputerGetData), true);
    service->UnRegisterInputer();
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
