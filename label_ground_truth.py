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


# - - - Ground Truth Labeling functions - CS events
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
                    set_cookies_split = header[1].split(
                        "\n"
                    )  # multiple set-cookie headers are concatenated with '\n' delimiting
                    for (
                        set_cookie_header
                    ) in (
                        set_cookies_split
                    ):  # extract each consecutive set-cookie header
                        if (
                            "expires" in set_cookie_header.lower()
                            or "max-age" in set_cookie_header.lower()
                        ):  # only consider non-session cookies
                            cookie_split = set_cookie_header.split(
                                ";"
                            )  # parse cookie value set in each header
                            cookie_value_split = cookie_split[0].split(
                                "="
                            )  # split cookie_name=cookie_ID....
                            if len(cookie_value_split) > 1:
                                set_cookie_headers.append(
                                    cookie_value_split[1]
                                )  # only consider cookie_ID.....

    # extract cookie IDs from parsed headers
    header_cookies = getResponseHeaderCookieStrings(set_cookie_headers)

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


def getResponseHeaderCookieStrings(strings: list[str]):
    cookies = []

    # extract cookie_id strings
    for string in strings:
        cookies_in_string = []  # list of cookie IDs found
        if string != None:
            id_matches = re.finditer(
                r"(?P<query>&[^=]*?=)?(?P<id>[a-zA-Z0-9_-]{11,})", string
            )
            id_matches_list = [i["id"] for i in id_matches]

        cookies.append(list(id_matches_list))

    # filter IDs by common false-positive words
    for edge_list in cookies:
        i = 0
        while i < len(edge_list):
            pop_check = False
            cookie_len = len(edge_list[i])
            for common_word in common_words:
                if common_word in edge_list[i].lower():
                    cookie_len -= len(common_word)
                    if cookie_len <= 10:
                        edge_list.pop(i)
                        pop_check = True
                        break
            if not pop_check:
                i += 1
    return cookies


def getSharedIDStrings(strings: list[str]):
    shared_ids = []

    # extract cookie_id strings
    for string in strings:
        cookies_in_string = []  # list of cookie IDs found
        if string != None:
            id_matches = re.finditer(
                r"(?P<query>&[^=]*?=)?(?P<id>[a-zA-Z0-9_-]{11,})", string
            )
            id_matches_list = [i["id"] for i in id_matches]

        shared_ids.append(list(id_matches_list))

    return shared_ids


def getRedirectIDSharingEvents(
    url_params: pd.Series(),
    requested_urls: pd.DataFrame,
    headers: pd.DataFrame,
    shared_with_third_party: list[int],
):

    param_shared_ids = []
    path_shared_ids = []

    url_paths = requested_urls.parallel_apply(getURLPaths)

    # getSharedIDStrings() returns a list of possible id-looking-strings for each edge (row) --> returns a 2D list
    param_ids = url_params.parallel_apply(getSharedIDStrings)
    path_ids = url_paths.parallel_apply(getSharedIDStrings)

    shared_with_third_party_df = pd.DataFrame(shared_with_third_party)

    # check for id sharing events and output lists of ids shared --> the first instance of an ID shared, is an ID sharing event
    data = [
        param_ids,
        path_ids,
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
            req_url,
            third_party_check,
        ) = row_values.to_numpy()

        # if third_party_check:  # only consider sharing with 3rd parties --> to be used if labeling party relations
        # or,
        if True:  # --> to be used if not labeling party relations
            if len(edge_param_ids) > 0 or len(edge_path_ids) > 0:
                id_shared.append(1)
            else:
                id_shared.append(0)
        else:
            id_shared.append(0)

    return (param_ids, path_ids, id_shared)


def idMatch(id: str, user_cookies: list[Cookie]):
    """Returns if id == a value in user_cookies"""
    for cookie in user_cookies:
        if cookie.value in id:
            return 1
    return 0


def incrementCSCount(req_url, endpoint_cs_count):
    resource = urlparse(req_url)

    if resource.hostname in endpoint_cs_count:
        endpoint_cs_count[resource.hostname] += 1
    else:
        endpoint_cs_count[resource.hostname] = 1
    return endpoint_cs_count


def getGroundTruthLabels(
    param_shared_ids: pd.DataFrame,
    path_shared_ids: pd.DataFrame,
    redirect_id_sharing_events: list[int],
    user_cookies: list[Cookie()],
    new_req_urls: pd.DataFrame,
):
    """
    labels each endpoint with
        0: no id share, no cookie sync
        -1: id share, unknown cookie sync
        1: id share, cookie sync
    :returns: list of ground truth labels, dict of each endpoint and their Csync count
    """
    ground_truth_labels = []
    endpoint_cs_count = {}

    id_sharing_df = pd.DataFrame(redirect_id_sharing_events)
    data = [
        param_shared_ids,
        path_shared_ids,
        id_sharing_df,
        new_req_urls,
    ]

    shared_ids_df = pd.concat(data, axis=1)

    for (i, row_values) in shared_ids_df.iterrows():
        (
            edge_param_id_list,
            edge_path_id_list,
            id_shared,
            req_url,
        ) = row_values.to_numpy()
        if id_shared:
            id_found = False
            for id in edge_param_id_list:
                if idMatch(id, user_cookies):
                    ground_truth_labels.append(1)
                    incrementCSCount(req_url, endpoint_cs_count)
                    id_found = True
                    break
            if not id_found:
                for id in edge_path_id_list:
                    if idMatch(id, user_cookies):
                        ground_truth_labels.append(1)
                        incrementCSCount(req_url, endpoint_cs_count)
                        id_found = True
                        break
            if not id_found:
                ground_truth_labels.append(-1)
        else:
            ground_truth_labels.append(0)

    return ground_truth_labels, endpoint_cs_count


def redirect_extraction(
    crawl_db,
    parallelize: bool,
    progress_bar: bool,
    verbose: bool,
    use_memory_fs: Union[bool, None],
    entity_dict: dict[str, str],
):
    global global_entity_dict

    # - - - SQL Data extraction
    connection = sqlite3.connect(crawl_db)

    new_req_urls = pd.read_sql("SELECT new_request_url FROM http_redirects", connection)

    old_req_urls = pd.read_sql("SELECT old_request_url FROM http_redirects", connection)

    headers = pd.read_sql("SELECT headers FROM http_redirects", connection)

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

    ground_truth_labels, endpoint_cs_count = getGroundTruthLabels(
        param_shared_ids,
        path_shared_ids,
        redirect_id_sharing_events,
        user_cookies,
        new_req_urls,
    )
    print(
        ground_truth_labels.count(1),
        "Cookie Sync events labelled out of",
        len(ground_truth_labels),
        "redirects",
    )
    print(
        ground_truth_labels.count(-1),
        "ID Share, unknown Cookie Sync events labelled out of",
        len(ground_truth_labels),
        "redirects",
    )
    print(
        ground_truth_labels.count(0),
        "No ID Share, No Cookie Sync events labelled out of",
        len(ground_truth_labels),
        "redirects",
    )
    print("Domain CS counts:")
    for x in endpoint_cs_count:
        print(x, endpoint_cs_count[x])
    # - - -

    redirect_features_df = pd.DataFrame()  # placeholder for Kev's features
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
