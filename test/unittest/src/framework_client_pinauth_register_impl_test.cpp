/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "framework_client_pinauth_register_impl_test.h"
#include "inputer_get_data_service.h"
#include "pin_auth_hdi.h"
#include "pin_auth_proxy.h"
#include "pin_auth_proxy_test.h"
#include "pinauth_register_impl.h"
#include "mock_inputer.h"
#include "mock_inputer_get_data_service.h"
#include "mock_pin_auth_interface.h"
#include "mock_pin_auth_service.h"
#include "mock_remote_object.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iremote_object.h"
#include "file_ex.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include <openssl/sha.h>

#define LOG_TAG "PIN_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void FrameworkClientPinAuthRegisterImplTest::SetUpTestCase()
{
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

void FrameworkClientPinAuthRegisterImplTest::TearDownTestCase()
{
}

void FrameworkClientPinAuthRegisterImplTest::SetUp()
{
}

void FrameworkClientPinAuthRegisterImplTest::TearDown()
{
}

HWTEST_F(FrameworkClientPinAuthRegisterImplTest, ResetProxyTest001, TestSize.Level0)
{
    sptr<MockPinAuthInterface> mock(new (std::nothrow) MockPinAuthInterface());
    EXPECT_CALL(*mock, RemoveDeathRecipient(_))
        .Times(Exactly(1))
        .WillOnce([](const sptr<MockPinAuthInterface::DeathRecipient> &recipient) {
            return true;
        });
    PinAuthRegisterImpl::Instance().proxy_ = iface_cast<PinAuthInterface>(mock);
    EXPECT_NE(PinAuthRegisterImpl::Instance().proxy_->AsObject(), nullptr);
    PinAuthRegisterImpl::Instance().ResetProxy(mock);
}

HWTEST_F(FrameworkClientPinAuthRegisterImplTest, OnRemoteDied001, TestSize.Level0)
{
    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) PinAuthRegisterImpl::PinAuthDeathRecipient());
    EXPECT_NO_THROW(dr->OnRemoteDied(nullptr));
}

HWTEST_F(FrameworkClientPinAuthRegisterImplTest, OnRemoteDied002, TestSize.Level0)
{
    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) PinAuthRegisterImpl::PinAuthDeathRecipient());
    sptr<MockPinAuthInterface> mock(new (std::nothrow) MockPinAuthInterface());
    EXPECT_CALL(*mock, RemoveDeathRecipient(_))
        .Times(Exactly(1))
        .WillOnce([](const sptr<MockPinAuthInterface::DeathRecipient> &recipient) {
            return true;
        });
    PinAuthRegisterImpl::Instance().proxy_ = iface_cast<PinAuthInterface>(mock);
    EXPECT_NO_THROW(dr->OnRemoteDied(mock));
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
