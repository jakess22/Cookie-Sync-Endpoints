import json
import os
import re
import pandas as pd
import sqlite3
import tldextract
from pandarallel import pandarallel
from urllib.parse import urlparse

# Citations:
# (1) KHALEESI/code/feature_extraction.ipynb --> https://github.com/uiowa-irl/Khaleesi/blob/main/code/feature_extraction.ipynb

entity_hash = ""


class Cookie:
    def __init__(self, host="host_unknown", value="no_value", is_session="no_value"):
        self.host = host
        self.value = value
        self.is_session = is_session

    def copy(self, other):
        self.host = other.host
        self.value = other.value
        self.is_session = other.is_session

    def display(self):
        print("(", self.host, ":", self.value, ")")


tracking_keywords = [
    "track",
    "ad",
    "bid",
    "cookie",
    "sync",
    "cs",
    "csync",
    "cssync",
    "cksync",
    "pixel",
    "rtb",
    "match",
    "cm",
    "usersync",
    "getuid",
    "uid",
    "gif",
    "bounce",
    "click",
    "measurement",
    "measure",
    "promoted",
    "pagead",
    "hit",
    "banner",
    "2mdn",
    "adsystem",
    "adsense",
    "ptracking",
    "beacon",
    "openx",
    "aralego",
    "usermatch",
    "appnexus",
    "popunder",
    "punder",
    "metrics",
    "tpid",
    "pixel",
    "idsync",
    "id_sync",
    "uuid",
    "uid",
    "advertising",
    "adsync",
    "dspid",
    "dpid",
    "dpuuid",
    "tracking",
    "delivery",
    "pid",
    "id_sync",
    "pxl",
    "1x1",
    "px",
    "pix",
    "analytics",
    "adserver",
    "bidder",
    "ads",
    "adform",
    "advert",
    "iframe",
    "googlead",
    "advertise",
    "prebid",
    "zoneid",
    "siteid",
    "pageid",
    "viewid",
    "zone_id",
    "google_afc",
    "google_afs",
    "google_gid",
    "google_cver",
    "pix",
    "rtb",
    "ssp",
    "dsp",
    "dmt",
    "sync",
    "doubleclick",
    "match",
    "tid",
    "google_nid",
    "google_dbm",
    "google_cm",
    "google_sc",
    "pagead",
    "measure",
    "promote",
    "banner",
    "2mdn",
    "adsystem",
    "adsense",
    "beacon",
    "opnex",
    "aralego",
    "usermatch",
    "metrics",
    "appnexus",
    "popunder",
    "punder",
    "tpid",
    "advertising",
    "iframe",
    "googlead",
    "collect",
    "switch",
    "swap",
]

# - - - helper functions

"""Check if a URL exists in inputted url_queries"""


def urlInQuery(req_query_strs: pd.DataFrame()):
    url_check = []
    for query in req_query_strs:
        if query != None:
            # standard check for URL
            regex = r"(?i)\b(([.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
            if len(re.findall(regex, query)) > 0:
                url_check.append(1)
            else:
                url_check.append(0)
        else:
            url_check.append(0)
    return url_check


"""Returns all url_queries in headers"""


def getHeaderQueries(headers: list[tuple]):
    url_in_query = []
    for header in headers:
        i = header[1].find("?")
        query_str = None
        if i != -1:
            split = header[1].split("?")
            raw_query = split[1]
            j = 0
            for char in raw_query:
                if char != '"':
                    j += 1
                else:
                    break
            query_str = split[1][:j]
        url_in_query.append(query_str)

    return url_in_query


def getTopLevelUrl(site_urls: list[tuple], header: list[tuple]):
    if len(site_urls) == 1:
        return site_urls[0][1]
    visit_id = header[0]

    for url in site_urls:
        if url[0] == visit_id:
            return url[1]


# - - - Feature extraction functions
def urlStringLength(urls: pd.DataFrame()):
    url_str_lens = []
    for url in urls:
        resource = urlparse(url)
        url_str_lens.append(len(resource.hostname))
    return url_str_lens


def getQueryStrings(urls: pd.DataFrame()):
    query_strs = []
    for url in urls:
        resource = urlparse(url)
        query_strs.append(resource.query)
    return query_strs


def getQueryStringLengths(queries: pd.DataFrame()):
    query_lengths = []
    for query in queries:
        if query != None:
            query_lengths.append(len(query))
        else:
            query_lengths.append(0)
    return query_lengths


def requestHeadersNumber(headers: pd.DataFrame()):
    request_header_count = []
    for header in headers:
        request_header_count.append(header.count("[") - 1)
    return request_header_count


def semicolonInQuery(query_strs: pd.DataFrame()):
    semicolon_query_check = []
    for (i, query) in query_strs.items():
        if query != None:
            if ";" in query:
                semicolon_query_check.append(1)
            else:
                semicolon_query_check.append(0)
        else:
            semicolon_query_check.append(0)
    return semicolon_query_check


def numberOfQueryCookies(query_strs: pd.DataFrame()):
    query_cookie_count = []
    for query in query_strs:
        cookie_count = []
        if query != None:
            cookie_count = getCookieStrings(query)

        query_cookie_count.append(len(cookie_count))
    return query_cookie_count


def urlContainsUUID(urls: pd.DataFrame()):
    uuid_check = []
    for url in urls:
        if "uid" in url[1] or "UID" in url[1] or "uuid" in url[1] or "UUID" in url[1]:
            uuid_check.append(1)
        else:
            # - - - Citation (1)
            regexUUID = re.compile(r"........-....-....-....-............")
            if regexUUID.search(url[1]):
                uuid_check.append(1)
            else:
                uuid_check.append(0)
            # - - -
    return uuid_check


def trackingKeywordsInUrl(urls: pd.DataFrame()):
    tracking_keyword_check = []
    for url in urls:
        keyword_found = False
        for keyword in tracking_keywords:
            if keyword in url:
                tracking_keyword_check.append(1)
                keyword_found = True
                break
        if not keyword_found:
            tracking_keyword_check.append(0)
    return tracking_keyword_check


def trackingKeywordsNextToSpecialChar(urls: pd.DataFrame()):
    keyword_char_adjacent_check = []

    for url in urls:
        keyword_found = False
        for keyword in tracking_keywords:
            # - - - Citation (1)
            regexKeywordsLeft = re.compile(r"[^0-9a-zA-Z]+" + keyword)
            regexKeywordsRight = re.compile(keyword + r"[^0-9a-zA-Z]")
            if regexKeywordsLeft.search(url) or regexKeywordsRight.search(url):
                keyword_char_adjacent_check.append(1)
                keyword_found = True
                break
            # - - -
        if not keyword_found:
            keyword_char_adjacent_check.append(0)
    return keyword_char_adjacent_check


def subdomainCheck(urls: pd.DataFrame()):
    subdomain_check = []

    for url in urls:
        tld = tldextract.extract(url)
        if tld.subdomain != None and tld.subdomain != "www":
            subdomain_check.append(1)
        else:
            subdomain_check.append(0)
    return subdomain_check


def specialCharCount(query_strs: pd.DataFrame()):
    special_char_count = []
    for (i, query) in query_strs.items():
        count = 0
        if query != None:
            for char in query:
                if not isinstance(char, int):
                    if not char.isalnum():
                        count += 1
        special_char_count.append(count)
    return special_char_count


def headerContainsSameSiteNone(headers: pd.DataFrame()):
    same_site_none_check = []

    for header in headers:
        if (
            "SameSite=None" in header
            or "samesite=none" in header
            or "SameSite=none" in header
            or "samesite=None" in header
        ):
            same_site_none_check.append(1)
        else:
            same_site_none_check.append(0)
    return same_site_none_check


def headerContainsP3P(headers: pd.DataFrame()):
    p3p_check = []
    for header in headers:
        if "p3p" in header or "P3P" in header:
            p3p_check.append(1)
        else:
            p3p_check.append(0)
    return p3p_check


def headerContainsETag(headers: pd.DataFrame()):
    etag_check = []
    for header in headers:
        if "etag" in header or "ETag" in header or "Etag" in header or "ETAG" in header:
            etag_check.append(1)
        else:
            etag_check.append(0)
    return etag_check


def requestURLContainsUUID(urls: pd.DataFrame()):
    uuid_check = []
    for url in urls:
        if "uid" in url or "UID" in url or "uuid" in url or "UUID" in url:
            uuid_check.append(1)
        else:
            # - - - Citation (1)
            regexUUID = re.compile(r"........-....-....-....-............")
            if regexUUID.search(url):
                uuid_check.append(1)
            else:
                uuid_check.append(0)
            # - - -
    return uuid_check


referrer_keywords = [
    "refUrl",
    "refurl",
    "refURL",
    "redir",
    "redirect",
    "refer",
    "referrer",
    "ref",
    "siteID",
    "site_id",
    "site_ID",
    "publisher",
    "nw",
    "ex",
    "partner",
    "receive",
    "rurl",
]


# - - - Ground Truth Labeling functions - CS events
"""Extract and return cookie_ids from a string"""


def getCookieStrings(strings: pd.DataFrame()):
    cookies = []

    # extract cookie_id strings
    for string in strings:
        cookies_in_string = set()  # list of cookie IDs found
        if string != None:
            # Citation (1): Khaleesi cookie extraction method
            if string.count("=") >= 1:
                cookie = string.split("=", 1)
                cookies_in_string |= set(re.split("[^a-zA-Z0-9_=&:-]", cookie[1]))
                cookies_in_string.add(cookie[1])
            # remove IDs <= 10 chars
            cookies_in_string = set([s for s in list(cookies_in_string) if len(s) > 10])

        cookies.append(list(cookies_in_string))

    # parse delimiters
    delimiters = [":", "&"]
    for edge_list in cookies:
        i = 0
        while i < len(edge_list):
            pop_check = False
            for delim in delimiters:
                if i < len(edge_list):
                    if delim in edge_list[i]:
                        split = edge_list[i].split(delim)
                        edge_list.pop(i)
                        pop_check = True
                        for val in split:
                            if len(val) > 10:
                                edge_list.append(val)
                    else:
                        continue
            if not pop_check:
                i += 1

    return cookies


"""Return cookie IDs in Set-Cookie header"""


def getResponseHeaderCookies(response_headers: list[tuple]):
    set_cookie_keywords = ["Set-Cookie", "Set-cookie", "set-cookie", "set-Cookie"]
    set_cookie_headers = []

    # make list of set-cookie header strings
    for header_str in response_headers:
        if header_str != None:
            header_json = json.loads(header_str[0])
            # header_json is an array of the format (0: key, 1: value)
            for keyword in set_cookie_keywords:
                for header in header_json:
                    if keyword == header[0]:
                        if (
                            "expires" in header[1] or "Expires" in header[1]
                        ):  # only consider non-session cookies
                            header_split = header[1].split(";")
                            set_cookie_headers.append(header_split[0])
                    else:
                        continue

    # extract cookie IDs from parsed headers
    header_cookies = getCookieStrings(set_cookie_headers)

    # filter dates picked up by getCookieStrings()
    for cookie_list in header_cookies:
        i = 0
        while i < len(cookie_list):
            regex_1 = re.compile(
                r"[0-9]{1,2}-[A-Z][a-z]{2}-[0-9]{2,4}"
            )  # 14-Jul-2022, 28-Jul-2022
            regex_2 = re.compile(
                r"[A-Z][a-z]{2}[0-9]{1,2}[A-Z][a-z]{2}[0-9]{2,4}"
            )  # Sat15Jul2023
            regex_3 = re.compile(
                r"[A-Z][a-z]{2}[0-9]{1,2}-[A-Z][a-z]{2}-[0-9]{2,4}"
            )  # Thu14-Jul-2022
            regex_4 = re.compile(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}"
            )  # 2022-08-01-21

            if re.fullmatch(regex_1, cookie_list[i]):
                if len(cookie_list) > 0:
                    cookie_list.pop(i)
                continue
            elif re.fullmatch(regex_2, cookie_list[i]):
                if len(cookie_list) > 0:
                    cookie_list.pop(i)
                continue
            elif re.fullmatch(regex_3, cookie_list[i]):
                if len(cookie_list) > 0:
                    cookie_list.pop(i)
                continue
            else:
                i += 1

    # filter IDs by common false-positive words
    common_words = [
        "Expires",
        "expires",
        "Path",
        "path",
        "Check",
        "check",
        "Permission",
        "permission",
        "Domain",
        "domain",
        "doubleclick",
        "media" "Secure",
        "secure",
        "None",
        "none",
        "Privacy",
        "privacy",
        "max",
        "MAX",
        "Max",
        "age",
        "AGE",
        "amazon",
        "adsystem",
        "secure",
        "Secure",
        "demdex" "casalemedia",
        "Only",
        "only",
        "Same",
        "same",
        "site",
        "Site",
        "rubicon",
        "project",
        "pubmatic",
        "yahoo",
        "cloudfare",
        "http",
        "HTTP",
        "com",
        "org" "comment",
        "Consent",
        "consent",
        "yahoo",
        "web",
        "platform",
        "microsoft",
        "market",
        "strict",
        "Strict",
        "Sync",
        "sync",
        "www",
        "user",
        "User",
        "cookie" "tag",
        "Tag",
        "comment",
        "Comment",
        "facebook",
        "smart",
        "server",
        "post",
        "bounce",
        "exchange",
        "express",
        "net",
        "world",
        "wide",
        "target",
        "network",
        "Network",
        "gdpr",
        "GDPR",
        "status",
        "code",
        "media",
        "found",
        "FOUND",
        "flash",
        "browser",
        "data",
        "test",
        "share",
        "pinterest",
        "personalization",
        "session",
        "Session",
        "cookie",
        "block",
        "Block",
        "Server",
        "server",
        "host",
        "Host",
        "Routing",
        "routing",
        "Key",
        "key",
        "captcha",
        "CAPTCHA",
        "enforce",
        "policy",
        "intuit",
        "connect",
        "route",
        "Flash",
        "flash",
        "match",
        "Match",
        "mobile",
        "acess",
        "Access",
    ]

    for cookie_list in header_cookies:
        i = 0
        while i < len(cookie_list):
            word_found = False
            for common_word in common_words:
                if common_word in cookie_list[i]:
                    cookie_list.pop(i)
                    word_found = True
                    break
            if not word_found:
                i += 1

    return header_cookies


"""Convert cookie_Tuple to Cookie objects"""
"""openWPM assigns the expiry of 9999-12-31T21:59:59.000Z
to cookies that do not have an expiration date (session cookies)"""


def makeCookieObjects(
    js_cookies: list[tuple],
    response_header_cookies: list[list[str]],
    response_headers: list[tuple],
):
    cookie_objects = []
    # convert js_cookies tuples to Cookie objects
    # js_cookie[0] = host
    # js_cooke[1] = value
    # js_cookie[2] = is_session
    for js_cookie in js_cookies:
        if not js_cookie[2]:  # filter session cookies (no expiration date)
            if len(js_cookie[1]) > 10:  # Pap. method string length requirement
                cookie_found = False
                for cookie in cookie_objects:  # prevent duplicate cookie IDs
                    if cookie.value == js_cookie[1]:
                        cookie_found = True
                        break
                if not cookie_found:  # create new Cookie object
                    resource = urlparse(js_cookie[0])
                    new_cookie_obj = Cookie(js_cookie[0], js_cookie[1], js_cookie[2])
                    cookie_objects.append(new_cookie_obj)

    # convert header_cookie strings to Cookie objects
    overlap = 0  # overlap between js_cookies and header_cookies, just out of curiosity
    for (header_cookie_list, response) in zip(
        response_header_cookies, response_headers
    ):
        for header_cookie in header_cookie_list:
            cookie_found = False
            for cookie_object in cookie_objects:  # prevent duplicate cookies
                if cookie_object.value == header_cookie:
                    cookie_found = True
                    break
            if not cookie_found:  # create new Cookie object
                resource = urlparse(response[1])
                new_cookie_obj = Cookie(host=resource.hostname, value=header_cookie)
                cookie_objects.append(new_cookie_obj)
            else:
                overlap += 1
    # print(overlap)
    return cookie_objects


"""Returns the organization a URL belongs to, if known"""


def findEntity(urls: pd.DataFrame()):
    entities = []

    for url in urls:
        url_tld = tldextract.extract(url)
        url_etld_plus_one = url_tld.domain + "." + url_tld.suffix

        found_entity = None
        try:
            found_entity = entity_hash[url_etld_plus_one]
        except KeyError:
            pass
        entities.append(found_entity)
    return entities


"""Checks if requested url is to a third party from the referrer."""


def sharedWithThirdParty(old_req_urls: pd.DataFrame(), new_req_urls: pd.DataFrame()):
    shared_with_third_party = []

    ref_entities = old_req_urls.parallel_apply(findEntity)
    req_entities = new_req_urls.parallel_apply(findEntity)

    for (index_1, ref_entity), (index_2, req_entity) in zip(
        ref_entities.iterrows(), req_entities.iterrows()
    ):
        # ref_entity, req_entity = Series() of length = 1

        if ref_entity[0] == None or req_entity[0] == None:
            shared_with_third_party.append(1)
        elif ref_entity[0] != req_entity[0]:
            shared_with_third_party.append(1)
        elif ref_entity[0] == req_entity[0]:
            shared_with_third_party.append(0)

    return shared_with_third_party


"""Adds unknown cookies to known_cookies map, returns id_sharing event if known cookie """


def checkIDisKnown(ids_to_check: list[str], req_url: str, known_ids: map):
    # ids_to_check: possibly new shared id-looking-strings in redirects
    # known_ids: map of id-looking-strings already discovered
    # ids_found: list of ids shared
    ids_shared = []

    for id_sub_list in ids_to_check:
        for id in id_sub_list:
            if id in known_ids:
                ids_shared.append(id)
            else:  # add to known_cookies map
                tld = tldextract.extract(req_url[0])
                known_ids[id] = tld.domain

    return ids_shared


"""Returns URL paths"""


def getURLPaths(urls: list[tuple]):
    paths = []
    for url in urls:
        resource = urlparse(url)
        paths.append(resource.path)
    return paths


"""Returns location headers"""


def getLocationHeader(headers: pd.Series()):
    location_headers = []

    for (index, header_str) in headers.items():
        if header_str != None:
            header_json = json.loads(header_str)
            # header_json is an array of the format (0: key, 1: value)
            header_found = False
            for header in header_json:
                if header[0] == "Location" or header[0] == "location":
                    location_headers.append(header[1])
                    header_found = True
                    break
                else:
                    continue
            if not header_found:
                location_headers.append("")
        else:
            location_headers.append("")

    return location_headers


"""Checks requested url parameters, reqeusted url paths, and request headers for instances of cookie like ID sharing"""


def getRedirectIDSharingEvents(
    url_params: pd.Series(),
    requested_urls: pd.DataFrame(),
    headers: pd.DataFrame(),
    shared_with_third_party: list[int],
):
    # (id-looking-string, url_domain)
    known_ids = {}

    shared_with_third_party_df = pd.DataFrame(shared_with_third_party)

    param_shared_ids = []
    path_shared_ids = []
    loc_header_shared_ids = []

    url_paths = requested_urls.parallel_apply(getURLPaths)
    location_headers = headers.parallel_apply(getLocationHeader)

    # getCookieStrings() returns a list of possible id-looking-strings for each edge (row) --> returns a 2D list
    param_ids = url_params.parallel_apply(getCookieStrings)
    path_ids = url_paths.parallel_apply(getCookieStrings)
    location_header_ids = location_headers.parallel_apply(getCookieStrings)

    # check for id sharing events and output lists of ids shared
    # ids_to_check: possibly new shared id-looking-strings in redirects
    # known_ids: map of id-looking-strings already discovered
    for (
        (i_1, edge_param_ids),
        (i_2, edge_path_ids),
        (i_3, edge_loc_header_ids),
        (i_4, req_url),
        (i_5, third_party_check),
    ) in zip(
        param_ids.iterrows(),
        path_ids.iterrows(),
        location_header_ids.iterrows(),
        requested_urls.iterrows(),
        shared_with_third_party_df.iterrows(),
    ):
        if third_party_check[0]:  # only consider sharing with 3rd parties
            found_param_ids = checkIDisKnown(
                edge_param_ids, req_url, known_ids
            )  # check if a user cookie_id shared in url parameters, else add to hash
            param_shared_ids.append(found_param_ids)

            found_path_ids = checkIDisKnown(
                edge_path_ids, req_url, known_ids
            )  # check if a user cookie_id shared in url path, else add to hash
            path_shared_ids.append(found_path_ids)

            found_loc_header_ids = checkIDisKnown(
                edge_loc_header_ids, req_url, known_ids
            )  # check if a user cookie_id shared in location header, else add to hash
            loc_header_shared_ids.append(found_loc_header_ids)
        else:
            empty_list = []
            param_shared_ids.append(empty_list)
            path_shared_ids.append(empty_list)
            loc_header_shared_ids.append(empty_list)

    # output list of id sharing events
    id_shared = []
    for (param, path, loc) in zip(
        param_shared_ids, path_shared_ids, loc_header_shared_ids
    ):
        if len(param) > 0 or len(path) > 0 or len(loc) > 0:
            id_shared.append(1)
        else:
            id_shared.append(0)

    return (
        param_shared_ids,
        path_shared_ids,
        loc_header_shared_ids,
        id_shared,
        known_ids,
    )


"""Returns if id == a value in user_cookies"""


def idMatch(id: str, user_cookies: list[Cookie()]):
    for cookie in user_cookies:
        if cookie.value == id:
            return 1
    return 0


"""Increments CS count for associated domain"""


def incrementCSCount(req_url, endpoint_cs_count):
    url_split = req_url[0].split("?")
    domain = url_split[0]

    if "http://" in domain:
        domain = domain[7:]
    elif "https://" in domain:
        domain = domain[8:]

    if domain in endpoint_cs_count:
        endpoint_cs_count[domain] += 1
    else:
        endpoint_cs_count[domain] = 1
    return endpoint_cs_count


"""Checks shared IDs against stored user IDs. If match --> cookie sync"""


def getCookieSyncs(
    param_shared_ids: list[list[str]],
    path_shared_ids: list[list[str]],
    loc_header_shared_ids: list[list[str]],
    redirect_id_sharing_events: list[int],
    user_cookies: list[Cookie()],
    new_req_urls_list: list[tuple],
):
    cookie_syncs = []
    endpoint_cs_count = {}

    for (
        edge_param_id_list,
        edge_path_id_list,
        edge_loc_id_list,
        id_shared,
        req_url,
    ) in zip(
        param_shared_ids,
        path_shared_ids,
        loc_header_shared_ids,
        redirect_id_sharing_events,
        new_req_urls_list,
    ):
        if id_shared:
            id_found = False
            for id in edge_param_id_list:
                if idMatch(id, user_cookies):
                    cookie_syncs.append(1)
                    domain_cs_count = incrementCSCount(req_url, endpoint_cs_count)
                    id_found = True
                    break
            if not id_found:
                for id in edge_path_id_list:
                    if idMatch(id, user_cookies):
                        cookie_syncs.append(1)
                        domain_cs_count = incrementCSCount(req_url, endpoint_cs_count)

                        id_found = True
                        break
            if not id_found:
                for id in edge_loc_id_list:
                    if idMatch(id, user_cookies):
                        cookie_syncs.append(1)
                        domain_cs_count = incrementCSCount(req_url, endpoint_cs_count)
                        id_found = True
                        break
            if not id_found:
                cookie_syncs.append(0)
        else:
            cookie_syncs.append(0)
    return cookie_syncs, endpoint_cs_count


# - - - end of ground truth labeling functions

# README: to add features, add feature column name to this list, and add corresponding object name down below
redirect_column_names = [
    "redirect_id_sharing_events",
    "url_str_lens",
    "req_header_num",
    "semicolon_in_query",
    "samesite_none_in_header",
    "p3p_in_header",
    "etag_in_header",
    "uuid_in_url",
    "tracking_keywords_next_to_special_char",
    "subdomain_check",
    "special_char_count",
    "req_query_str_lens",
    "req_query_cookies_num",
    "tracking_keywords_in_url",
    "query_url_check",
    "cookie_syncs",
]


def redirect_extraction(
    crawl_db,
    parallelize: bool,
    progress_bar: bool,
    verbose: bool,
    use_memory_fs: bool,
    entity_map: map,
):
    # README: only using top 100 sites + 8 case study crawls for alpha testing. Will adjust implementation to handle whole dataset when it is ready
    # README: if only testing a feature function, do not run getRedirectIDSharingEvents(). It takes a long time and will slow down your testing.

    global entity_hash

    # - - - SQL Data extraction
    connection = sqlite3.connect(crawl_db)
    cursor = connection.cursor()

    cursor.execute("SELECT new_request_url FROM http_redirects")
    new_req_urls_list = cursor.fetchall()
    new_req_urls = pd.DataFrame(new_req_urls_list)

    cursor.execute("SELECT old_request_url FROM http_redirects")
    old_req_urls = pd.DataFrame(cursor.fetchall())

    cursor.execute("SELECT response_status FROM http_redirects")
    # add to list
    response_codes = pd.DataFrame(cursor.fetchall())

    cursor.execute("SELECT headers FROM http_redirects")
    headers = pd.DataFrame(cursor.fetchall())

    cursor.execute("SELECT site_url FROM site_visits")
    site_urls = pd.DataFrame(cursor.fetchall())

    cursor.execute("SELECT host, value, is_session FROM javascript_cookies")
    js_cookies = cursor.fetchall()

    cursor.execute("SELECT headers, url FROM http_responses")
    response_headers = cursor.fetchall()

    connection.close()
    # - - -

    if parallelize:
        # nb_workers (cores) defaults to number available
        pandarallel.initialize(
            progress_bar=progress_bar, verbose=verbose, use_memory_fs=use_memory_fs
        )
    else:
        pandarallel.initialize(
            nb_workers=1,
            progress_bar=progress_bar,
            verbose=verbose,
            use_memory_fs=use_memory_fs,
        )

    """README: if only testing a feature function, do not run sharedWithThirdParty(). It takes a long time and will slow down your testing."""
    # - - - Papadapolous Method
    req_query_strs = new_req_urls.parallel_apply(getQueryStrings)

    req_query_str_lens = req_query_strs.parallel_apply(getQueryStringLengths)

    # do not add to redirect_features_df
    response_header_cookies = getResponseHeaderCookies(response_headers)

    user_cookies = makeCookieObjects(
        js_cookies, response_header_cookies, response_headers
    )

    entity_hash = entity_map  # necessary for pandarallelization format constraints
    shared_with_third_party = sharedWithThirdParty(old_req_urls, new_req_urls)

    (
        param_shared_ids,
        path_shared_ids,
        loc_header_shared_ids,
        redirect_id_sharing_events,
        known_cookies,
    ) = getRedirectIDSharingEvents(
        req_query_strs, new_req_urls, headers, shared_with_third_party
    )
    print(
        sum(redirect_id_sharing_events),
        "ID Sharing events labelled out of ",
        len(redirect_id_sharing_events),
        "redirects\n",
    )

    cookie_syncs, endpoint_cs_count = getCookieSyncs(
        param_shared_ids,
        path_shared_ids,
        loc_header_shared_ids,
        redirect_id_sharing_events,
        user_cookies,
        new_req_urls_list,
    )
    print(
        sum(cookie_syncs),
        "Cookie Sync events labelled out of ",
        len(cookie_syncs),
        "redirects\n",
    )

    print("Domain CS counts:")
    for x in endpoint_cs_count:
        print(x, endpoint_cs_count[x])
    # - - -

    # - - - Explicit Features:
    req_query_cookies_num = req_query_strs.parallel_apply(numberOfQueryCookies)
    # - - -

    # - - - Non-Explicit Features: features to be used only for ML classifier. Not needed to label CSyncs
    tracking_keywords_in_url = new_req_urls.parallel_apply(trackingKeywordsInUrl)
    url_str_lens = new_req_urls.parallel_apply(urlStringLength)
    req_header_num = headers.parallel_apply(requestHeadersNumber)
    semicolon_in_query = req_query_strs.parallel_apply(semicolonInQuery)
    samesite_none_in_header = headers.parallel_apply(headerContainsSameSiteNone)
    p3p_in_header = headers.parallel_apply(headerContainsP3P)
    etag_in_header = headers.parallel_apply(headerContainsETag)
    uuid_in_url = new_req_urls.parallel_apply(requestURLContainsUUID)
    tracking_keywords_next_to_special_char = new_req_urls.parallel_apply(
        trackingKeywordsNextToSpecialChar
    )
    subdomain_check = new_req_urls.parallel_apply(subdomainCheck)
    special_char_count = req_query_strs.parallel_apply(specialCharCount)
    query_url_check = req_query_strs.parallel_apply(urlInQuery)
    # - - -

    # README: to add features, add feature object to this list, and add corresponding column name to redirect_column_names list above
    redirect_id_sharing_events_df = pd.DataFrame(redirect_id_sharing_events)
    cookie_syncs_df = pd.DataFrame(cookie_syncs)
    data = [
        redirect_id_sharing_events_df,
        url_str_lens,
        req_header_num,
        semicolon_in_query,
        samesite_none_in_header,
        p3p_in_header,
        etag_in_header,
        uuid_in_url,
        tracking_keywords_next_to_special_char,
        subdomain_check,
        special_char_count,
        req_query_str_lens,
        req_query_cookies_num,
        tracking_keywords_in_url,
        query_url_check,
        cookie_syncs_df,
    ]
    redirect_features_df = pd.concat(data, axis=1, keys=redirect_column_names)
    return redirect_features_df


def feature_extraction(
    crawl_db,
    parallelize: bool,
    progress_bar: bool,
    verbose: bool,
    use_memory_fs: bool,
    entity_map: map,
):
    redirect_features_df = redirect_extraction(
        crawl_db, parallelize, progress_bar, verbose, use_memory_fs, entity_map
    )
    return redirect_features_df
