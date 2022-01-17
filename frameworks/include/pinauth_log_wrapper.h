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

#ifndef PINAUTH_LOG_WRAPPER_H
#define PINAUTH_LOG_WRAPPER_H

#define CONFIG_HILOG
#ifdef CONFIG_HILOG

#include <string>
#include "hilog/log.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
#define FILENAME            (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define FORMATED(fmt, ...)    "[%{public}s] %{public}s# " fmt, FILENAME, __FUNCTION__, ##__VA_ARGS__

#ifdef PINAUTH_HILOGF
#undef PINAUTH_HILOGF
#endif

#ifdef PINAUTH_HILOGE
#undef PINAUTH_HILOGE
#endif

#ifdef PINAUTH_HILOGW
#undef PINAUTH_HILOGW
#endif

#ifdef PINAUTH_HILOGI
#undef PINAUTH_HILOGI
#endif

#ifdef PINAUTH_HILOGD
#undef PINAUTH_HILOGD
#endif

enum PinAuthModule {
    MODULE_INNERKIT = 0,
    MODULE_SERVICE,
    MODULE_COMMON,
    MODULE_FRAMEWORKS,
    MODULE_JS_NAPI,
    PINAUTH_MODULE_BUTT,
};

static constexpr unsigned int BASE_PINAUTH_DOMAIN_ID = 0xD002910;

enum PinAuthDomainId {
    PINAUTH_INNERKIT_DOMAIN = BASE_PINAUTH_DOMAIN_ID + MODULE_INNERKIT,
    PINAUTH_SERVICE_DOMAIN,
    COMMON_DOMAIN,
    PINAUTH_JS_NAPI,
    PINAUTH_BUTT,
};

static constexpr OHOS::HiviewDFX::HiLogLabel PINAUTH_LABEL[PINAUTH_MODULE_BUTT] = {
    {LOG_CORE, PINAUTH_INNERKIT_DOMAIN, "PinAuth"},
    {LOG_CORE, PINAUTH_SERVICE_DOMAIN, "PinAuthService"},
    {LOG_CORE, COMMON_DOMAIN, "PinAuthCommon"},
    {LOG_CORE, PINAUTH_JS_NAPI, "PinAuthJSNAPI"},
};

#define PINAUTH_HILOGF(module, ...) (void)OHOS::HiviewDFX::HiLog::Fatal(PINAUTH_LABEL[module], FORMATED(__VA_ARGS__))
#define PINAUTH_HILOGE(module, ...) (void)OHOS::HiviewDFX::HiLog::Error(PINAUTH_LABEL[module], FORMATED(__VA_ARGS__))
#define PINAUTH_HILOGW(module, ...) (void)OHOS::HiviewDFX::HiLog::Warn(PINAUTH_LABEL[module], FORMATED(__VA_ARGS__))
#define PINAUTH_HILOGI(module, ...) (void)OHOS::HiviewDFX::HiLog::Info(PINAUTH_LABEL[module], FORMATED(__VA_ARGS__))
#define PINAUTH_HILOGD(module, ...) (void)OHOS::HiviewDFX::HiLog::Debug(PINAUTH_LABEL[module], FORMATED(__VA_ARGS__))
}  // namespace PinAuth
}  // namespace UserIAM
}  // namespace OHOS

#else

#define PINAUTH_HILOGF(...)
#define PINAUTH_HILOGE(...)
#define PINAUTH_HILOGW(...)
#define PINAUTH_HILOGI(...)
#define PINAUTH_HILOGD(...)

#endif // CONFIG_HILOG

#endif  // PINAUTH_LOG_WRAPPER_H