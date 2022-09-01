import json
import re
import pandas as pd
import sqlite3
import tldextract
from pandarallel import pandarallel
from typing import Union
from urllib.parse import urlparse

# Citations:
# (1) KHALEESI/code/feature_extraction.ipynb --> https://github.com/uiowa-irl/Khaleesi/blob/main/code/feature_extraction.ipynb

global_entity_dict = ""


with open("./word_lists/tracking.txt") as f:
    tracking_keywords = [word for word in f.read().strip().split("\n")]

with open("./word_lists/common.txt") as f:
    common_words = [word for word in f.read().strip().split("\n")]

with open("./word_lists/referrer.txt") as f:
    referrer_keywords = [word for word in f.read().strip().split("\n")]


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


# - - - helper functions
def urlInQuery(req_query_strs: pd.DataFrame) -> list[int]:
    """
    Check if a URL exists in inputted url_queries
    :param req_query_strs: DataFrame of queries to check
    :returns: list of 0s and 1s corresponding to whether each query had a URL or not
              0: no URL in query
              1: URL in query
    """
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


def getHeaderQueries(headers: list[tuple]) -> list[str]:
    """
    Gets all url_queries in headers
    :param headers: list of URL headers to extract header queries from
    :returns: list of header queries corresponding to each header
    """
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


def getTopLevelUrl(site_urls: list[tuple], header: list[tuple]) -> Union[str, None]:
    """
    Gets the top level url
    :param site_urls:
    :param header:
    :returns: the top level url
    """
    if len(site_urls) == 1:
        return site_urls[0][1]
    visit_id = header[0]

    for url in site_urls:
        if url[0] == visit_id:
            return url[1]


# - - - Feature extraction functions
def urlStringLength(urls: pd.DataFrame) -> list[int]:
    """
    Creates a list of URL string lengths
    :param url: DataFrame of URLs
    :returns: list of URL string lengths
    """
    url_str_lens = []
    for url in urls:
        resource = urlparse(url)
        url_str_lens.append(len(resource.hostname))
    return url_str_lens


def getQueryStrings(urls: pd.DataFrame) -> list[str]:
    """
    Creates a list of URL query strings
    :param url: DataFrame of URLs
    :returns: list of URL query strings
    """
    query_strs = []
    for url in urls:
        resource = urlparse(url)
        query_strs.append(resource.query)
    return query_strs


def getQueryStringLengths(queries: pd.DataFrame) -> list[int]:
    """
    Creates a list of URL query string lengths
    :param url: DataFrame of URL queries
    :returns: list of URL query string lenghts
    """
    query_lengths = []
    for query in queries:
        if query != None:
            query_lengths.append(len(query))
        else:
            query_lengths.append(0)
    return query_lengths


def requestHeadersNumber(headers: pd.DataFrame) -> list[int]:
    """
    Creates a list of URL header counts
    :param url: DataFrame of URL headers
    :returns: list of URL header counts
    """
    request_header_count = []
    for header in headers:
        request_header_count.append(header.count("[") - 1)
    return request_header_count


def semicolonInQuery(query_strs: pd.DataFrame) -> list[int]:
    """
    Checks if there is a semicolon in each of the URL query in the list
    :param query_strs: DataFrame of queries to check
    :returns: list of 0s and 1s corresponding to whether each query had a semicolon or not
              0: no semicolon in query
              1: semicolon in query
    """
    semicolon_query_check = []
    for query in query_strs.values:
        if query != None:
            if ";" in query:
                semicolon_query_check.append(1)
            else:
                semicolon_query_check.append(0)
        else:
            semicolon_query_check.append(0)
    return semicolon_query_check


def numberOfQueryCookies(query_strs: pd.DataFrame) -> list[int]:
    """
    Gets the number of query cookies for each URL query in the list
    :param query_strs: DataFrame of queries to check
    :returns: list of number of query cookies corresponding to each query in query_strs
    """
    query_cookie_count = []
    for query in query_strs:
        cookie_count = []
        if query != None:
            cookie_count = getURLCookieStrings(query)

        query_cookie_count.append(len(cookie_count))
    return query_cookie_count


def urlContainsUUID(urls: pd.DataFrame) -> list[int]:
    """
    Checks if UUID keyword is in each of the URLs in the list
    :param urls: DataFrame of URLs to check
    :returns: list of 0s and 1s corresponding to whether each URL had a UUID keyword in it or not
              0: no UUID keyword in URL
              1: UUID keyword in URL
    """
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


def trackingKeywordsInUrl(urls: pd.DataFrame) -> list[int]:
    """
    Checks if any tracking keywords are found in each of the URLs in the list
    :param urls: DataFrame of URLs to check
    :returns: list of 0s and 1s corresponding to whether each URL had any tracking keywords or not
              0: no tracking keywords in URL
              1: at least 1 tracking keyword in URL
    """
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


def trackingKeywordsNextToSpecialChar(urls: pd.DataFrame) -> list[int]:
    """
    Checks if any tracking keywords are next to a special character (non-alphanumeric) in each of the URLs in the list
    :param urls: DataFrame of URLs to check
    :returns: list of 0s and 1s corresponding to whether any tracking keywords are next to a special character
              0: no tracking keyword next to special character in URL
              1: at least 1 tracking keyword next to special character in URL
    """
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


def subdomainCheck(urls: pd.DataFrame) -> list[int]:
    """
    Checks if there is a subdomain in each of the URLs in the list
    :param urls: DataFrame of URLs to check
    :returns: list of 0s and 1s corresponding to whether there was a subdomain in the URL
              0: no subdomain exists
              1: yes subdomain exists
    """
    subdomain_check = []

    for url in urls:
        tld = tldextract.extract(url)
        if tld.subdomain != None and tld.subdomain != "www":
            subdomain_check.append(1)
        else:
            subdomain_check.append(0)
    return subdomain_check


def specialCharCount(query_strs: pd.DataFrame) -> list[int]:
    """
    Gets the number of special characters (non-alphanumeric) for each of the queries in the list
    :param query_strs: DataFrame of queries to check
    :returns: list of special character counts corresponding to each query
    """
    special_char_count = []
    for query in query_strs.values:
        count = 0
        if query != None:
            for char in query:
                if not isinstance(char, int):
                    if not char.isalnum():
                        count += 1
        special_char_count.append(count)
    return special_char_count


def headerContainsSameSiteNone(headers: pd.DataFrame) -> list[int]:
    """
    Checks if samesite is none in each of the URL headers in the list
    :param headers: DataFrame of URL headers to check
    :returns: list of 0s and 1s corresponding to whether samesite was none in each header
              0: samesite NOT none
              1: samesite none
    """
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


def headerContainsP3P(headers: pd.DataFrame) -> list[int]:
    """
    Checks if P3P is in each of the URL headers in the list
    :param headers: DataFrame of URL headers to check
    :returns: list of 0s and 1s corresponding to whether P3P in each header
              0: P3P NOT in header
              1: P3P in header
    """
    p3p_check = []
    for header in headers:
        if "p3p" in header or "P3P" in header:
            p3p_check.append(1)
        else:
            p3p_check.append(0)
    return p3p_check


def headerContainsETag(headers: pd.DataFrame) -> list[int]:
    """
    Checks if ETag is in each of the URL headers in the list
    :param headers: DataFrame of URL headers to check
    :returns: list of 0s and 1s corresponding to whether ETag in each header
              0: ETag NOT in header
              1: ETag in header
    """
    etag_check = []
    for header in headers:
        if "etag" in header or "ETag" in header or "Etag" in header or "ETAG" in header:
            etag_check.append(1)
        else:
            etag_check.append(0)
    return etag_check


def requestURLContainsUUID(urls: pd.DataFrame) -> list[int]:
    """
    Checks if UUID keyword is in each of the URL request headers in the list
    :param headers: DataFrame of URL request headers to check
    :returns: list of 0s and 1s corresponding to whether UUID keyword in each header
              0: UUID keyword NOT in header
              1: UUID in header
    """
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


# - - - Ground Truth Labeling functions - CS events
def getHeaderCookieStrings(strings: list[str]):
    """Extract and return cookie_ids from header string"""

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


def getResponseHeaderCookies(response_headers: pd.DataFrame):
    """return cookie_ids from header"""

    set_cookie_headers = []

    # make list of set-cookie header strings
    for (i, header_str) in response_headers.iterrows():
        # header_str[0] = header
        # header_str[1] = url

        if header_str[0] != None:
            header_json = json.loads(header_str[0])
            # header_json[0] is an array of the format (0: key, 1: value)
            for header in header_json:
                if header[0].lower() == "set-cookie":
                    if (
                        "expires" in header[1] or "Expires" in header[1]
                    ):  # only consider non-session cookies
                        header_split = header[1].split(";")
                        set_cookie_headers.append(header_split[0])

    # extract cookie IDs from parsed headers
    header_cookies = getHeaderCookieStrings(set_cookie_headers)

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
            elif re.fullmatch(regex_4, cookie_list[i]):
                if len(cookie_list) > 0:
                    cookie_list.pop(i)
                continue
            else:
                i += 1

    # filter IDs by common false-positive words
    for cookie_list in header_cookies:
        i = 0
        while i < len(cookie_list):
            word_found = False
            for common_word in common_words:
                if common_word in cookie_list[i].lower():
                    cookie_list.pop(i)
                    word_found = True
                    break
            if not word_found:
                i += 1
    return header_cookies


def makeCookieObjects(
    js_cookies: pd.DataFrame,
    response_header_cookies: list[list[str]],
    response_headers: pd.DataFrame,
):
    """Convert cookie_Tuple to Cookie objects"""
    """openWPM assigns the expiry of 9999-12-31T21:59:59.000Z
    to cookies that do not have an expiration date (session cookies)"""

    cookie_objects = []
    # convert js_cookies tuples to Cookie objects
    # js_cookie[0] = host
    # js_cooke[1] = value
    # js_cookie[2] = is_session
    for (i, js_cookie) in js_cookies.iterrows():
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
    # reponse_headers[0] = header
    # response_headers[1] = response url
    overlap = 0  # overlap between js_cookies and header_cookies, just out of curiosity
    response_headers_list = response_headers.values.tolist()
    for (header_cookie_list, response) in zip(
        response_header_cookies, response_headers_list
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


def findEntity(urls: pd.DataFrame) -> list[str]:
    """Returns the organization a URL belongs to, if known"""
    entities = []

    for url in urls:
        url_tld = tldextract.extract(url)
        url_etld_plus_one = url_tld.domain + "." + url_tld.suffix

        found_entity = None
        try:
            found_entity = global_entity_dict[url_etld_plus_one]
        except KeyError:
            pass
        entities.append(found_entity)
    return entities


def sharedWithThirdParty(
    old_req_urls: pd.DataFrame, new_req_urls: pd.DataFrame
) -> list[int]:
    """Checks if requested url is to a third party from the referrer."""
    shared_with_third_party = []

    ref_entities = old_req_urls.parallel_apply(findEntity)
    req_entities = new_req_urls.parallel_apply(findEntity)

    for (index_1, ref_entity), (index_2, req_entity) in zip(
        ref_entities.iterrows(), req_entities.iterrows()
    ):
        # ref_entity, req_entity = Series of length = 1

        if ref_entity[0] == None or req_entity[0] == None:
            shared_with_third_party.append(1)
        elif ref_entity[0] != req_entity[0]:
            shared_with_third_party.append(1)
        elif ref_entity[0] == req_entity[0]:
            shared_with_third_party.append(0)

    return shared_with_third_party


def getURLPaths(urls: pd.DataFrame):
    paths = []
    for url in urls:
        resource = urlparse(url)
        paths.append(resource.path)
    return paths


def getLocationHeader(headers: pd.Series):
    location_headers = []

    for (index, header_str) in headers.items():
        if header_str != None:
            header_json = json.loads(header_str)
            # header_json is an array of the format (0: key, 1: value)
            header_found = False
            for header in header_json:
                if header[0].lower() == "location":
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


def getURLCookieStrings(strings: list[str]):
    cookies = []

    # extract cookie_id strings
    for string in strings:
        cookies_in_string = []  # list of cookie IDs found
        if string != None:
            id_matches = re.finditer(
                r"(?P<query>&[^=]*?=)?(?P<id>[a-zA-Z0-9_-]{10,})", string
            )
            id_matches_list = [i["id"] for i in id_matches]

        cookies.append(list(id_matches_list))

    # filter IDs by common false-positive words
    for edge_list in cookies:
        i = 0
        while i < len(edge_list):
            word_found = False
            for common_word in common_words:
                if common_word in edge_list[i].lower():
                    edge_list.pop(i)
                    word_found = True
                    break
            if not word_found:
                i += 1

    return cookies


def getRedirectIDSharingEvents(
    url_params: pd.Series(),
    requested_urls: pd.DataFrame,
    headers: pd.DataFrame,
    shared_with_third_party: list[int],
):

    param_shared_ids = []
    path_shared_ids = []
    loc_header_shared_ids = []

    url_paths = requested_urls.parallel_apply(getURLPaths)
    location_headers = headers.parallel_apply(getLocationHeader)

    # getCookieStrings() returns a list of possible id-looking-strings for each edge (row) --> returns a 2D list
    param_ids = url_params.parallel_apply(getURLCookieStrings)
    path_ids = url_paths.parallel_apply(getURLCookieStrings)
    location_header_ids = location_headers.parallel_apply(getURLCookieStrings)

    shared_with_third_party_df = pd.DataFrame(shared_with_third_party)

    # check for id sharing events and output lists of ids shared --> the first instance of an ID shared, is an ID sharing event
    data = [
        param_ids,
        path_ids,
        location_header_ids,
        requested_urls,
        shared_with_third_party_df,
    ]
    known_ids_df = pd.concat(data, axis=1)

    # check for id sharing events
    id_shared = []
    for (i, row_values) in known_ids_df.iterrows():
        (
            edge_param_ids,
            edge_path_ids,
            edge_loc_header_ids,
            req_url,
            third_party_check,
        ) = row_values.to_numpy()

        if third_party_check:  # only consider sharing with 3rd parties
            if (
                len(edge_param_ids) > 0
                or len(edge_path_ids) > 0
                or len(edge_loc_header_ids) > 0
            ):
                id_shared.append(1)
            else:
                id_shared.append(0)
        else:
            id_shared.append(0)

    return (param_ids, path_ids, location_header_ids, id_shared)


def idMatch(id: str, user_cookies: list[Cookie]):
    """Returns if id == a value in user_cookies"""
    for cookie in user_cookies:
        if cookie.value in id:
            return 1
    return 0


def incrementCSCount(req_url, endpoint_cs_count):
    resource = urlparse(req_url[0])

    if resource.hostname in endpoint_cs_count:
        endpoint_cs_count[resource.hostname] += 1
    else:
        endpoint_cs_count[resource.hostname] = 1
    return endpoint_cs_count


def getHeuristicCookieSyncs(
    param_shared_ids: pd.DataFrame,
    path_shared_ids: pd.DataFrame,
    loc_header_shared_ids: pd.DataFrame,
    redirect_id_sharing_events: list[int],
    user_cookies: list[Cookie()],
    new_req_urls: pd.DataFrame,
):
    cookie_syncs = []
    endpoint_cs_count = {}

    id_sharing_df = pd.DataFrame(redirect_id_sharing_events)
    data = [
        param_shared_ids,
        path_shared_ids,
        loc_header_shared_ids,
        id_sharing_df,
        new_req_urls,
    ]

    shared_ids_df = pd.concat(data, axis=1)

    for (i, row_values) in shared_ids_df.iterrows():
        (
            edge_param_id_list,
            edge_path_id_list,
            edge_loc_id_list,
            id_shared,
            req_url,
        ) = row_values.to_numpy()
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
    "heuristic_cookie_syncs",
]


def redirect_extraction(
    crawl_db,
    parallelize: bool,
    progress_bar: bool,
    verbose: bool,
    use_memory_fs: Union[bool, None],
    entity_dict: dict[str, str],
):
    # README: only using top 100 sites + 8 case study crawls for alpha testing. Will adjust implementation to handle whole dataset when it is ready
    # README: if only testing a feature function, do not run getRedirectIDSharingEvents(). It takes a long time and will slow down your testing.

    global global_entity_dict

    # - - - SQL Data extraction
    connection = sqlite3.connect(crawl_db)

    new_req_urls = pd.read_sql("SELECT new_request_url FROM http_redirects", connection)

    old_req_urls = pd.read_sql("SELECT old_request_url FROM http_redirects", connection)

    # response_codes = pd.read_sql("SELECT response_status FROM http_redirects", connection)

    headers = pd.read_sql("SELECT headers FROM http_redirects", connection)

    # site_urls = pd.read_sql("SELECT site_url FROM site_visits", connection)

    js_cookies = pd.read_sql(
        "SELECT host, value, is_session FROM javascript_cookies", connection
    )

    response_headers = pd.read_sql(
        "SELECT headers, url FROM http_responses", connection
    )

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

    # - - - CSync Heuristic Labeling Method
    req_query_strs = new_req_urls.parallel_apply(getQueryStrings)

    req_query_str_lens = req_query_strs.parallel_apply(getQueryStringLengths)

    # do not add to redirect_features_df
    response_header_cookies = getResponseHeaderCookies(response_headers)

    user_cookies = makeCookieObjects(
        js_cookies, response_header_cookies, response_headers
    )

    global_entity_dict = (
        entity_dict  # necessary for pandarallelization format constraints
    )
    shared_with_third_party = sharedWithThirdParty(old_req_urls, new_req_urls)

    (
        param_shared_ids,
        path_shared_ids,
        loc_header_shared_ids,
        redirect_id_sharing_events,
    ) = getRedirectIDSharingEvents(
        req_query_strs, new_req_urls, headers, shared_with_third_party
    )
    print(
        sum(redirect_id_sharing_events),
        "ID Sharing events labelled out of ",
        len(redirect_id_sharing_events),
        "redirects\n",
    )

    heuristic_cookie_syncs, endpoint_cs_count = getHeuristicCookieSyncs(
        param_shared_ids,
        path_shared_ids,
        loc_header_shared_ids,
        redirect_id_sharing_events,
        user_cookies,
        new_req_urls,
    )
    print(
        sum(heuristic_cookie_syncs),
        "Cookie Sync events labelled out of ",
        len(heuristic_cookie_syncs),
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
    heuristic_cookie_syncs_df = pd.DataFrame(heuristic_cookie_syncs)
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
        heuristic_cookie_syncs_df,
    ]
    redirect_features_df = pd.concat(data, axis=1, keys=redirect_column_names)
    return redirect_features_df, endpoint_cs_count, user_cookies


def feature_extraction(
    crawl_db,
    parallelize: bool,
    progress_bar: bool,
    verbose: bool,
    use_memory_fs: Union[bool, None],
    entity_dict: dict[str, str],
):
    redirect_features_df = redirect_extraction(
        crawl_db, parallelize, progress_bar, verbose, use_memory_fs, entity_dict
    )
    return redirect_features_df
