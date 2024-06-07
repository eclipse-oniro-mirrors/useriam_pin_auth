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
#define private public
#include "framework_client_pinauth_register_impl_test.h"
#include "pin_auth_hdi.h"
#include "pinauth_register_impl.h"
#include "mock_pin_auth_interface.h"
#include "mock_remote_object.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iremote_object.h"

#include <openssl/sha.h>

#define LOG_TAG "PIN_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void FrameworkClientPinAuthRegisterImplTest::SetUpTestCase()
{
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
    MockPinAuthInterface mock;
    EXPECT_CALL(mock, RemoveDeathRecipient(_))
        .Times(Exactly(1))
        .WillOnce([](const sptr<MockPinAuthInterface::DeathRecipient> &recipient) {
            return true;
        });
    sptr<MockPinAuthInterface> mockPinAuthInterface = &mock;
    PinAuthRegisterImpl::Instance().proxy_ = iface_cast<PinAuthInterface>(mockPinAuthInterface);
    EXPECT_NE(PinAuthRegisterImpl::Instance().proxy_->AsObject(), nullptr);
    sptr<IRemoteObject> objReset = &mock;
    PinAuthRegisterImpl::Instance().ResetProxy(objReset);
    PinAuthRegisterImpl::Instance().proxy_ = iface_cast<PinAuthInterface>(mockPinAuthInterface);
}

HWTEST_F(FrameworkClientPinAuthRegisterImplTest, OnRemoteDied001, TestSize.Level0)
{
    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) PinAuthRegisterImpl::PinAuthDeathRecipient());
    EXPECT_NO_THROW(dr->OnRemoteDied(nullptr));
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
