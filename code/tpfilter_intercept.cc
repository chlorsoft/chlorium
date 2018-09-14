#include "url/gurl.h"
#include "content/public/common/resource_type.h"

#ifdef ADB_TESTER
#include <cstddef>
#include <cstdlib>
#include <string.h>

#include "log.h"
#include <tld.h>

#else

#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include <android/log.h>

#endif

#include "net/url_request/tpfilter_entries.h"

namespace net {

const char *LOG_TAG = "Chlorium";

#ifdef ADB_TESTER
int tpfilter_rules_count() { return TPFILTER_ENTRY_COUNT; }
#endif

// True if the given canonical |host| is "[www.]<domain_in_lower_case>.<TLD>"
// with a valid TLD. If |subdomain_permission| is ALLOW_SUBDOMAIN, we check
// against host "*.<domain_in_lower_case>.<TLD>" instead. Will return the TLD
// string in |tld|, if specified and the |host| can be parsed.
static bool is_first_party(char *l_host, char *l_url_host) {
  size_t tld_length;

#ifdef ADB_TESTER
  char *found_tld;

  if (TLD_SUCCESS != tld_get_z(l_host, &found_tld))
    return false;
  tld_length = strlen(found_tld);
  if (tld_length == 0)
    return false;
#else
  tld_length = net::registry_controlled_domains::GetCanonicalHostRegistryLength(
      l_host, net::registry_controlled_domains::EXCLUDE_UNKNOWN_REGISTRIES,
      net::registry_controlled_domains::EXCLUDE_PRIVATE_REGISTRIES);
  if ((tld_length == 0) || (tld_length == std::string::npos))
    return false;
#endif

  int len = strlen(l_host);
  char *tld = l_host + len - tld_length;

  // Removes any subdomain from origin host.
  int i = len - tld_length - 2, top_i = i;
  if (i < 0) {
    return false;
  }
  char *domain = l_host;
  for (; i >= 0; i--) {
    if (l_host[i] == '.') {
      int p_len = top_i - i;
      // skip "co" in "co.uk", "org" in "org.uk"
      if (p_len <= 3) {
        tld -= p_len + 1;
        continue;
      }

      // segment is long enough, accept it at as a domain
      domain = l_host + i;
      len -= i;
      break;
    }
  }

#ifdef TPFILTER_LOG
  __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                      "%s: extracted domain suffix: \"%s\" (TLD=\"%s\")",
                      l_host, domain, tld);
#endif

  // Check if supplied URL host matches, including the dot.
  int b_len = strlen(l_url_host);
  if (b_len < len) {
    return false;
  }
  for (int i = 0; i < len; i++) {
    if (l_url_host[b_len - 1 - i] != domain[len - 1 - i])
      return false;
  }

  // pass with flying colors
  return true;
}

static char *strtolower(const char *str) {
  int len = strlen(str);
  char *ret = (char *)malloc(len + 1);
  ret[len] = '\0';
  for (int i = 0; i < len; i++) {
    if ((65 <= str[i]) && (str[i] <= 90)) {
      ret[i] = str[i] + 32;
    } else {
      ret[i] = str[i];
    }
  }
  return ret;
}

static char *strtosep(const char *str) {
  int len = strlen(str);
  char *ret = (char *)malloc(len + 3);
  ret[0] = '^';
  ret[len + 1] = '^';
  ret[len + 2] = '\0';
  for (int i = 0; i < len; i++) {
    if ((str[i] == ':') || (str[i] == '/') || (str[i] == '?') ||
        (str[i] == '&') || (str[i] == '=')) {
      ret[i + 1] = '^';
    } else {
      ret[i + 1] = str[i];
    }
  }
  return ret;
}

static bool url_matches(const char *c_url, char *c_url_sep, char *c_url_lower,
                        char *c_url_lower_sep, tpfilter_entry *entry) {
  bool match = false;
  // select comparison string based on case and separator presence (separator
  // takes some shortcuts)
  bool match_case = ((entry->flags & TPFILTER_FLAG_MATCH_CASE) != 0);
  bool match_separator = ((entry->flags & TPFILTER_FLAG_HAS_SEPARATOR) != 0);
  const char *match_url =
      match_case ? (match_separator ? c_url_sep : c_url)
                 : (match_separator ? c_url_lower_sep : c_url_lower);

#ifdef TPFILTER_LOG_MORE
  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[case:%d][sep:%d][%s]",
                      match_case, match_separator, match_url);
#endif
  // check for all match parts at >= position of last match
  const char *last = match_url;
  for (int m = 0; const char *url_match = entry->matches[m]; m++) {
    bool is_last_match = entry->matches[m + 1] == NULL;
    const char *pos = strstr(last, url_match);
    match = (pos != NULL);

#ifdef TPFILTER_LOG_MORE
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%s][found:%d][match:%d]",
                        entry->matches[m], pos == NULL ? 0 : 1, match ? 1 : 0);
#endif
    // check if the url starts with the first match part
    if (match && (m == 0) && ((entry->flags & TPFILTER_FLAG_MATCH_BEGIN) != 0) &&
        (pos != match_url))
      match = false;

    // check if the url ends with the last match part
    if (match && is_last_match &&
        ((entry->flags & TPFILTER_FLAG_MATCH_END) != 0) &&
        (pos != &match_url[strlen(match_url) - strlen(entry->matches[m])]))
      match = false;

    // check domain match
    if (match && (m == 0) &&
        ((entry->flags & TPFILTER_FLAG_MATCH_DOMAIN) != 0) &&
        (pos != match_url) && (pos[-1] != '^') && (pos[-1] != '.') &&
        (pos[-1] != '/'))
      match = false;

    // short circuit
    if (!match)
      break;
  }
  return match;
}

bool url_match_domain(tpfilter_entry *entry, const std::string &origin_host) {
  bool match_domain = true;
  // check for a negative domain match
  if (entry->domains_skip) {
    if (origin_host.empty()) {
      // skip this rule, cannot match on domain
      return false;
    }
    for (int d = 0; const char *domain = entry->domains_skip[d]; d++) {
      if (domain == origin_host) {
        match_domain = false;
        break;
      }
    }
  }

  // check for a required positive domain match
  if (entry->domains) {
    if (origin_host.empty()) {
      // skip this rule, cannot match on domain
      return false;
    }
    for (int d = 0; const char *domain = entry->domains[d]; d++) {
      if (domain != origin_host) {
        match_domain = false;
        break;
      }
    }
  }
  return match_domain;
}

static bool url_match_party(tpfilter_entry *entry, const GURL &url,
                            const std::string &origin_host, bool &checked_fp,
                            bool &fp) {
  bool wanted_fp;
  if ((entry->flags & TPFILTER_FLAG_THIRD_PARTY) != 0) {
    wanted_fp = false;
  } else if ((entry->flags & TPFILTER_FLAG_FIRST_PARTY) != 0) {
    wanted_fp = true;
  } else {
    // no-op
    return true;
  }

  if (origin_host.empty()) {
    // cannot match this rule, no origin host to determine first/third party
    return false;
  }

#ifdef ADB_TESTER
//__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "matchFirst=%d matchThird=%d",
// matchFirstParty, matchThirdParty);
#endif
  if (!checked_fp) {
    // lower-case version
    char *l_host = strtolower(origin_host.c_str()),
         *l_url_host = strtolower(url.host().c_str());

    // is the URL a first-party to the current page's host?
    fp = is_first_party(l_host, l_url_host);

    checked_fp = true;
#ifdef ADB_TESTER
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "is_first_party(\"%s\", \"%s\") = %s", l_host,
                        l_url_host, fp ? "true" : "false");
#endif
    free(l_host);
    free(l_url_host);
  }

  return fp == wanted_fp;
}

int tpfilter_intercept(const GURL &url, const std::string &origin_host, content::ResourceType resource_type) {
  if (url.is_valid() && url.SchemeIsHTTPOrHTTPS()) {
    const char *c_url = url.spec().c_str();
    char *c_url_lower = strtolower(c_url);
    char *c_url_sep = strtosep(c_url);
    char *c_url_lower_sep = strtosep(c_url_lower);

#ifdef TPFILTER_LOG
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%s with host '%s'] [%s]",
                        c_url, url.host().c_str(), origin_host.c_str());
#endif

    bool checked_fp = false, fp = false;

    bool intercept = false;
    for (int i = 0; i < TPFILTER_ENTRY_COUNT; i++) {
      tpfilter_entry *entry = &TPFILTER_ENTRIES[i];

      // no use checking rules when we're intercepting, or exceptions when not
      bool check =
          (!intercept && ((entry->flags & TPFILTER_FLAG_EXCEPTION) == 0)) ||
          (intercept && ((entry->flags & TPFILTER_FLAG_EXCEPTION) != 0));
      if (!check)
        continue;

      // first check for domain matches, a quick branch out if matching
      if (!url_match_domain(entry, origin_host))
        continue;

      // check on the URL matcher
      if (!url_matches(c_url, c_url_sep, c_url_lower, c_url_lower_sep, entry))
        continue;

      // finally check first/third-party
      if (!url_match_party(entry, url, origin_host, checked_fp, fp))
        continue;

#ifdef TPFILTER_LOG
      if (!intercept) {
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                            "--> intercept (#%d: \"%s\") (%x)", i,
                            entry->matches[0], entry->flags);
      } else {
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "--> pass (%d) (#%d)", i,
                            entry->flags);
      }
#endif
      intercept = !intercept;
    } // for each entry

    free(c_url_sep);
    free(c_url_lower);
    free(c_url_lower_sep);

    if (intercept) {
#ifdef TPFILTER_LOG
      __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "blocked");
#endif
      return 1;
    }
#ifdef TPFILTER_LOG
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "pass");
#endif
  }
  return 0;
}

} // namespace net
