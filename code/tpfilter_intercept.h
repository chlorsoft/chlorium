#ifndef NET_URL_REQUEST_TPFILTER_INTERCEPT_H_
#define NET_URL_REQUEST_TPFILTER_INTERCEPT_H_

#include "url/gurl.h"
#include "content/public/common/resource_type.h"

namespace net {

#ifdef ADB_TESTER
int tpfilter_rules_count();
#endif

int tpfilter_intercept(const GURL &url, const std::string &origin_host, content::ResourceType resource_type);

} // namespace net

#endif // NET_URL_REQUEST_TPFILTER_INTERCEPT_H_
