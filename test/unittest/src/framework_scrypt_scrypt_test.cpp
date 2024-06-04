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

#include "framework_scrypt_scrypt_test.h"
#include "scrypt.h"
#include "mock_inputer_set_data.h"

#include <openssl/sha.h>

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void FrameworkScryptScryptTest::SetUpTestCase()
{
}

void FrameworkScryptScryptTest::TearDownTestCase()
{
}

void FrameworkScryptScryptTest::SetUp()
{
}

void FrameworkScryptScryptTest::TearDown()
{
}

HWTEST_F(FrameworkScryptScryptTest, GetScryptTest001, TestSize.Level0)
{
    std::vector<uint8_t> algoParameter = {1, 2, 3, 4, 5};
    Scrypt scrypt(algoParameter);
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    uint32_t algoVersion = 1;
    std::vector<uint8_t> result = scrypt.GetScrypt(data, algoVersion);
    EXPECT_EQ(result.size(), 0);
}

HWTEST_F(FrameworkScryptScryptTest, GetScryptTest002, TestSize.Level0)
{
    std::vector<uint8_t> algoParameter = {1, 2, 3, 4, 5};
    Scrypt scrypt(algoParameter);
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    uint32_t algoVersion = 100;
    std::vector<uint8_t> result = scrypt.GetScrypt(data, algoVersion);
    EXPECT_EQ(result.size(), 0);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
