import pandas as pd
import csv
import sqlite3
import tldextract
import re
import os
import json

# Citations:
# (1) KHALEESI/code/feature_extraction.ipynb --> https://github.com/uiowa-irl/Khaleesi/blob/main/code/feature_extraction.ipynb

tracking_keywords = ['track', 'ad', 'bid', 'cookie', 'sync', 'cs', 'csync', 'cssync', 'cksync', 'pixel', 'rtb', 'match',\
	'cm', 'usersync', 'getuid', 'uid', 'gif', 'bounce', "click", "measurement", "measure", "promoted", "pagead", "hit", "banner", "2mdn",\
               "adsystem", "adsense", "ptracking", "beacon", "openx", "aralego", "usermatch",\
               "appnexus", "popunder", "punder", "metrics", "tpid", "pixel", "idsync", 'id_sync', "uuid",\
               "uid", "advertising", "adsync", "dspid", "dpid", "dpuuid", "tracking", "delivery",\
               "pid", "id_sync", "pxl", "1x1", "px", "pix", "analytics", "adserver",\
               "bidder", "ads", "adform", "advert", "iframe", "googlead", "advertise", "prebid",\
                "zoneid", "siteid", "pageid", "viewid", "zone_id", "google_afc" , "google_afs",\
               "google_gid", "google_cver", "pix", "rtb", "ssp", "dsp", "dmt", "sync", "doubleclick",\
               "match", "tid", "google_nid", "google_dbm", "google_cm", "google_sc", 'pagead', 'measure', 'promote',\
			   'banner', '2mdn', 'adsystem', 'adsense', 'beacon', 'opnex', 'aralego', 'usermatch', 'metrics', 'appnexus',\
		   	'popunder', 'punder', 'tpid', 'advertising', 'iframe', 'googlead', 'collect', 'switch', 'swap']

class Cookie:
	def __init__(self, visit_id=0, expiry='no_value', host='none', value='no_value', same_site='no_value'):
		self.visit_id = visit_id
		self.expiry = expiry
		self.host = host
		self.value = value
		self.same_site = same_site

	def copy(self, other):
		self.visit_id = other.visit_id
		self.expiry = other.expiry
		self.host = other.host
		self.value = other.value
		self.same_site = other.same_site

	def display(self):
		print(self.value)

# - - - helper functions
def getHeaderCookieCount(header_substring: str):
	cookie_count = 0
	if header_substring != None:
		# find alphanumeric strings >= 14
		id_size = 0
		equal_sign_found = False
		for char in header_substring:
			if char == '=':
				equal_sign_found = True
				continue
			if equal_sign_found:
				if char.isalnum() or char == '-':
					id_size += 1
				else:
					id_size = 0
					equal_sign_found = False
					# only increment cookie_count once per cookie_size >= 14 detection
				if id_size == 14:
					cookie_count += 1

	return cookie_count

"""Check if a URL exists in inputted url_queries"""
def urlInQuery(req_query_strs: list[tuple]):
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
		i = header[1].find('?')
		query_str = None
		if i != -1:
			split = header[1].split('?')
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

"""Check if a domain was shared in a header"""
def headerDomainShared(headers: list[tuple]):
	header_domain_shared = []
	for header in headers:
		if header[1] != 'None':
			if ('p3p' in header[1] or 'P3P' in header[1]) and 'policyref' in header[1]:
				header_domain_shared.append(1)
			elif ('set-cookie' in header[1] or 'Set-Cookie' in header[1]) and ('domain' in header[1] or 'Domain' in header[1]):
				header_domain_shared.append(1)
			else:
				header_domain_shared.append(0)

	return header_domain_shared

def getTopLevelUrl(site_urls: list[tuple], header: list[tuple]):
	if len(site_urls) == 1:
		return site_urls[0][1]
	visit_id = header[0]

	for url in site_urls:
		if url[0] == visit_id:
			return url[1]

"""Extract and return cookie_ids from a string"""
def getCookieStrings(strings: list[str]):
	cookies = []

	for x in strings:
		sub_list = []
		if x != None:
			# find alphanumeric strings >= 10
			cookie_id = ''
			for char in x:
				if char.isalnum() or char == '-':
					cookie_id += char
				elif len(cookie_id) >= 10:
					sub_list.append(cookie_id)
					cookie_id = ''
				else:
					cookie_id = ''
		cookies.append(sub_list)
	return cookies
# - - -

# - - - Feature extraction functions
def urlStringLength(urls: list[tuple]):
	url_str_lens = []
	for url in urls:
		i = url[1].find('?')
		url_len = len(url[1])
		if i != -1:
			split = url[1].split('?')
			url_len = len(split[0])
		url_str_lens.append(url_len)
	return url_str_lens

def queryStringLength(urls: list[tuple]):
	query_str_lens = []
	query_strs = []
	for url in urls:
		i = url[1].find('?')
		query_len = 0
		query_str = None
		if i != -1:
			split = url[1].split('?')
			query_len = len(split[1])
			query_str = split[1]
		query_str_lens.append(query_len)
		query_strs.append(query_str)
	return query_str_lens, query_strs

def requestHeadersNumber(headers: list[tuple]):
	request_header_count = []
	for header in headers:
		request_header_count.append(header[1].count('[') - 1)
	return request_header_count

def semicolonInQuery(query_strs: list[str]):
	semicolon_query_check = []
	for query in query_strs:
		if query != None:
			if ';' in query:
				semicolon_query_check.append(1)
			else:
				semicolon_query_check.append(0)
	return semicolon_query_check

def numberOfQueryCookies(query_strs: list[str]):
	#cid_keywords ['user_id', 'USER_ID', 'uuid', 'pid', 'cid']
	# ^ not used, another detection option

	query_cookie_count = []
	for query in query_strs:
		cookie_count = []
		if query != None:
			cookie_count = getCookieStrings(query)

		query_cookie_count.append(len(cookie_count))
	return query_cookie_count

def numberOfHeaderCookies(headers: list[tuple]):
	header_cookie_count = []
	for header in headers:
		cookie_count = 0
		set_cookie_found = False
		if 'Set-Cookie' in header[1]:
			i = header[1].find("Set-Cookie")
			set_cookie_found = True
		elif 'set-cookie' in header[1]:
			i = header[1].find("set-cookie")
			set_cookie_found = True
		if set_cookie_found:
			if i != -1:
				i += len("Set-Cookie\",") + 1
				j = i + 1
				while header[1][j] != ']':
					j += 1
				set_cookie_substring = header[1][i:j]
				cookie_count = getHeaderCookieCount(set_cookie_substring)
		header_cookie_count.append(cookie_count)

	return header_cookie_count

def urlContainsUUID(urls: list[tuple]):
	uuid_check = []
	for url in urls:
		if 'uid' in url[1] or 'UID' in url[1] or 'uuid' in url[1] or 'UUID' in url[1]:
			uuid_check.append(1)
		else:
			# - - - Citation (1)
			regexUUID = re.compile(r'........-....-....-....-............')
			if regexUUID.search(url[1]):
				uuid_check.append(1)
			else:
				uuid_check.append(0)
			# - - -
	return uuid_check

def trackingKeywordsInUrl(urls: list[tuple]):
	tracking_keyword_check = []
	for url in urls:
		keyword_found = False
		for keyword in tracking_keywords:
			if keyword in url[1]:
				tracking_keyword_check.append(1)
				keyword_found = True
				break
		if not keyword_found:
			tracking_keyword_check.append(0)
	return tracking_keyword_check

def trackingKeywordsNextToSpecialChar(urls: list[tuple]):
	keyword_char_adjacent_check = []

	for url in urls:
		keyword_found = False
		for keyword in tracking_keywords:
			# - - - Citation (1)
			regexKeywordsLeft = re.compile(r'[^0-9a-zA-Z]+' + keyword)
			regexKeywordsRight = re.compile(keyword + r'[^0-9a-zA-Z]')
			if regexKeywordsLeft.search(url[1]) or regexKeywordsRight.search(url[1]):
				keyword_char_adjacent_check.append(1)
				keyword_found = True
				break
			# - - -
		if not keyword_found:
				keyword_char_adjacent_check.append(0)
	return keyword_char_adjacent_check

def subdomainCheck(urls: list[tuple]):
	subdomain_check = []

	for url in urls:
		tld = tldextract.extract(url[1])
		if tld.subdomain != None and tld.subdomain != 'www':
			subdomain_check.append(1)
		else:
			subdomain_check.append(0)
	return subdomain_check

def specialCharCount(query_strs: list[tuple]):
	special_char_count = []
	for query in query_strs:
		count = 0
		if query != None:
			for char in query:
				if not isinstance(char, int):
					if not char.isalnum():
						count += 1
		special_char_count.append(count)
	return special_char_count

def headerContainsSameSiteNone(headers: list[tuple]):
	same_site_none_check = []

	for header in headers:
		if "SameSite=None" in header[1] or 'samesite=none' in header[1] or 'SameSite=none' in header[1] or 'samesite=None' in header[1]:
			same_site_none_check.append(1)
		else:
			same_site_none_check.append(0)
	return same_site_none_check

def headerContainsP3P(headers: list[tuple]):
	p3p_check = []
	for header in headers:
		if 'p3p' in header[1] or 'P3P' in header[1]:
			p3p_check.append(1)
		else:
			p3p_check.append(0)
	return p3p_check

def headerContainsETag(headers: list[tuple]):
	etag_check = []
	for header in headers:
		if 'etag' in header[1] or 'ETag' in header[1] or 'Etag' in header[1] or 'ETAG' in header[1]:
			etag_check.append(1)
		else:
			etag_check.append(0)
	return etag_check

def requestURLContainsUUID(urls: list[tuple]):
	uuid_check = []
	for url in urls:
		if 'uid' in url[1] or 'UID' in url[1] or 'uuid' in url[1] or 'UUID' in url[1]:
			uuid_check.append(1)
		else:
			# - - - Citation (1)
			regexUUID = re.compile(r'........-....-....-....-............')
			if regexUUID.search(url[1]):
				uuid_check.append(1)
			else:
				uuid_check.append(0)
			# - - -
	return uuid_check

"""Returns whether (ref_url, req_url) tuple is to a third party"""
def newDomainCheck(old_req_urls: list[tuple], new_req_urls: list[tuple]):
	domain_check = []

	for (referrer, request) in zip(old_req_urls, new_req_urls):
		tld_ref = tldextract.extract(referrer[1])
		tld_req = tldextract.extract(request[1])

		if tld_ref.domain == tld_req.domain and tld_ref.suffix == tld_req.suffix:
			domain_check.append(0)
		else:
			domain_check.append(1)
	return domain_check

referrer_keywords = ['refUrl', 'refurl', 'refURL', 'redir', 'redirect', 'refer', 'referrer',\
'ref', 'siteID', 'site_id', 'site_ID', 'publisher', 'nw', 'ex', 'partner', 'receive', 'rurl']

"""Convert cookie_Tuple to Cookie objects"""
"""openWPM assigns the expiry of 9999-12-31T21:59:59.000Z
to cookies that do not have an expiration date (session cookies)"""
def makeCookieObjects(js_cookies: list[tuple]):
	cookie_objects = []
	for js_cookie in js_cookies:
		if js_cookie[1] != '9999-12-31T21:59:59.000Z':
			new_cookie_obj = Cookie(js_cookie[0], js_cookie[1], js_cookie[2], js_cookie[3], js_cookie[4])
			cookie_objects.append(new_cookie_obj)
	return cookie_objects

"""Checks for delimiters in cookies and splits cookie_ID if found. Will update old cookie.value with first split,
and make new cookie object with the second split."""
"""Not finalized"""
def parseDelimiters(cookies: list[Cookie()]):
	delimiters = [':', '&']
	i = 0
	for cookie in cookies:
		for d in delimiters:
			if d in cookie.value:
				split = cookie.value.split(d)

				# update initial cookie value with newly parsed value
				cookie.value = split[0]

				# make new cookie with other parsed value, sharing all other element values as original (i.e host, expiration)
				new_cookie = Cookie()
				new_cookie.copy(cookie)
				new_cookie.value = split[1]
				cookies.append(new_cookie)
	return cookies

"""Checks if requested url is to a third party from the referrer. First checks PS+1, then uses entity map lookup. """
def sharedWithThirdParty(ref_url: str, req_url: str, entity_map: json):
	ref_tld = tldextract.extract(ref_url)
	req_tld = tldextract.extract(req_url)

	if ref_tld.domain == req_tld.domain:
		if ref_tld.suffix == req_tld.suffix:
			return False # shared with first party

	ref_entity = ''
	req_entity = ''
	# find referrer entity in map
	for entity in entity_map:
		for property in entity_map[entity]['properties']:
			prop_tld = tldextract.extract(property)
			if prop_tld.domain == ref_tld.domain:
				if prop_tld.suffix == ref_tld.suffix:
					ref_entity = entity
	# find request entity in map
	for entity in entity_map:
		for property in entity_map[entity]['properties']:
			prop_tld = tldextract.extract(property)
			if prop_tld.domain == req_tld.domain:
				if prop_tld.suffix == req_tld.suffix:
					req_entity = entity

	if ref_entity != req_entity:
		return 1
	else:
		return 0

"""Adds unknown cookies to known_cookies map, returns id_sharing event if known cookie """
def checkCookieIsKnown(cookies_to_check, ref_url, req_url, known_cookies, entity_map):
	cookies_found = []

	if sharedWithThirdParty(ref_url, req_url, entity_map):
		for cookie_to_check in cookies_to_check:
			if cookie_to_check in known_cookies:
				cookies_found.append(cookie_to_check)
			else:
				tld = tldextract.extract(req_url)
				known_cookies[cookie_to_check] = tld.domain

	return cookies_found

"""Returns URL paths"""
def getURLPaths(urls: list[tuple]):
	paths = []
	for url in urls:
		resource_name = url[1]

		i = resource_name.find('http://')
		if i != -1: # remove scheme
			split = resource_name.split('http://')
			resource_name = split[1]
		i = resource_name.find('https://')
		if i != -1: # remove scheme
			split = resource_name.split('https://')
			resource_name = split[1]

		i = resource_name.find('?')
		if i != -1: # remove parameters
			split = resource_name.split('?')
			resource_name = split[0]
		i = resource_name.find('/')
		if i != -1:
			split = resource_name.split('/', 1)
			path = split[1]
			paths.append(path)
		else:
			path.append(None)

	return paths

"""Returns location headers"""
def getLocationHeader(headers: list[tuple]):
	location_headers = []
	for header in headers:
		i = header[1].find('location')
		if i != -1:
			j = i + len('location') + 3
			k = 0
			header_substring = header[1][j:]
			for char in header_substring:
				if char == '"':
					break
				k += 1
			location_header = header_substring[:k]
			location_headers.append(location_header)
		else:
			i = header[1].find('Location')
			if i != -1:
				j = i + len('Location') + 3
				k = 0
				header_substring = header[1][j:]
				for char in header_substring:
					if char == '"':
						break
					k += 1
				location_header = header_substring[:k]
				location_headers.append(location_header)
	return location_headers

"""Checks requested url parameters, reqeusted url paths, and request headers for instances of cookie like ID sharing"""
def getRedirectIDSharingEvents(url_params: list[tuple], referrer_urls: list[tuple], requested_urls: list[tuple], headers: list[tuple]):
	# (cookie_ID, url_domain)
	known_cookies = {}

	param_shared_ids = []
	path_shared_ids = []
	loc_header_shared_ids = []

	url_paths = getURLPaths(requested_urls)
	location_headers = getLocationHeader(headers)
	# later, check Set-Cookie header too

	# getCookieStrings() returns a list of possible cookie_ids for each edge (row) --> returns a 2D list
	param_cookies = getCookieStrings(url_params)
	path_cookies = getCookieStrings(url_paths)
	location_header_cookies = getCookieStrings(location_headers)

	# load json of known organization domain names
	entity_json = open("entity_map.json")
	entity_map = json.load(entity_json)

	# check for id sharing events and output lists of ids shared
	for (edge_param_cookies, edge_path_cookies, edge_loc_header_cookies, ref_url, req_url) in zip(param_cookies, path_cookies, location_header_cookies, referrer_urls, requested_urls):
		found_param_cookies = checkCookieIsKnown(edge_param_cookies, ref_url[1], req_url[1], known_cookies, entity_map) # check if a user cookie_id shared in url parameters, else add to hash
		param_shared_ids.append(found_param_cookies)

		found_path_cookies = checkCookieIsKnown(edge_path_cookies, ref_url[1], req_url[1], known_cookies, entity_map) # check if a user cookie_id shared in url path, else add to hash
		path_shared_ids.append(found_path_cookies)

		found_loc_header_cookies = checkCookieIsKnown(edge_loc_header_cookies, ref_url[1], req_url[1], known_cookies, entity_map) # check if a user cookie_id shared in location header, else add to hash
		loc_header_shared_ids.append(found_loc_header_cookies)

	# output list of id sharing events
	id_shared = []
	for (param, path, loc) in zip(param_shared_ids, path_shared_ids, loc_header_shared_ids):
		if len(param) > 0 or len(path) > 0 or len(loc) > 0:
			id_shared.append(1)
		else:
			id_shared.append(0)

	return param_shared_ids, path_shared_ids, loc_header_shared_ids, id_shared, known_cookies

"""Returns if id == a value in user_cookies"""
def idMatch(id: str, user_cookies: list[Cookie()]):
	for cookie in user_cookies:
		if cookie.value == id:
			return 1
	return 0

"""Checks shared IDs against stored user IDs. If match --> cookie sync"""
def getCookieSyncs(param_shared_ids: list[list[str]], path_shared_ids: list[list[str]], loc_header_shared_ids: list[list[str]], redirect_id_sharing_events: list[int], user_cookies: list[Cookie()]):
	cookie_syncs = []

	for (edge_param_id_list, edge_path_id_list, edge_loc_id_list, id_shared) in zip(param_shared_ids, path_shared_ids, loc_header_shared_ids, redirect_id_sharing_events):
		if id_shared:
			id_found = False
			for id in edge_param_id_list:
				if idMatch(id, user_cookies):
					cookie_syncs.append(1)
					id_found = True
					break
			if not id_found:
				for id in edge_path_id_list:
					if idMatch(id, user_cookies):
						cookie_syncs.append(1)
						id_found = True
						break
			if not id_found:
				for id in edge_loc_id_list:
					if idMatch(id, user_cookies):
						cookie_syncs.append(1)
						id_found = True
						break
			if not id_found:
				cookie_syncs.append(0)
		else:
			cookie_syncs.append(0)
	return cookie_syncs



# README: to add features, add feature column name to this list, and add corresponding object name down below
redirect_column_names = ['param_shared_ids', 'path_shared_ids', 'loc_header_shared_ids', 'redirect_id_sharing_events', 'url_str_lens', 'req_header_num', 'semicolon_in_query', 'samesite_none_in_header',\
	'p3p_in_header', 'etag_in_header', 'uuid_in_url', 'tracking_keywords_next_to_special_char', 'subdomain_check',\
	'special_char_count', 'req_query_str_lens', 'req_query_cookies', 'header_cookies_num',\
	'tracking_keywords_in_url', 'new_domain_check', 'query_url_check', 'cookie_syncs']


def redirect_extraction(crawl_db):
	# README: only using top 100 sites + 8 case study crawls for alpha testing. Will adjust implementation to handle whole dataset when it is ready
	# README: if only testing a feature function, do not run getRedirectIDSharingEvents(). It takes a long time and will slow down your testing.

	# - - - SQL Data extraction
	connection = sqlite3.connect(crawl_db)
	cursor = connection.cursor()

	cursor.execute("SELECT visit_id, new_request_url FROM http_redirects")
	new_req_urls = cursor.fetchall()

	cursor.execute("SELECT visit_id, old_request_url FROM http_redirects")
	old_req_urls = cursor.fetchall()

	cursor.execute("SELECT response_status FROM http_redirects")
	# add to list
	response_codes = cursor.fetchall()

	cursor.execute("SELECT visit_id, headers FROM http_redirects")
	headers = cursor.fetchall()

	cursor.execute("SELECT visit_id, site_url FROM site_visits")
	site_urls = cursor.fetchall()

	cursor.execute("SELECT visit_id, expiry, host, value, same_site FROM javascript_cookies")
	js_cookies = cursor.fetchall()

	connection.close()
	# - - -

	"""README: if only testing a feature function, do not run getRedirectIDSharingEvents(). It takes a long time and will slow down your testing."""
	# - - - Papadapolous Method
	req_query_str_lens, req_query_strs = queryStringLength(new_req_urls)
	user_cookies = makeCookieObjects(js_cookies)
	user_cookies = parseDelimiters(user_cookies)

	param_shared_ids, path_shared_ids, loc_header_shared_ids, redirect_id_sharing_events, known_cookies = getRedirectIDSharingEvents(req_query_strs, old_req_urls, new_req_urls, headers)
	print(sum(redirect_id_sharing_events), 'ID Sharing events labelled out of ', len(redirect_id_sharing_events), 'redirects')

	cookie_syncs = getCookieSyncs(param_shared_ids, path_shared_ids, loc_header_shared_ids, redirect_id_sharing_events, user_cookies)
	print(sum(cookie_syncs), 'Cookie Sync events labelled out of ', len(cookie_syncs), 'redirects')
	# - - -


	# - - - Explicit Features:
	req_query_cookies = numberOfQueryCookies(req_query_strs)
	# - - -

	# - - - Non-Explicit Features: features to be used only for ML classifier. Not needed to label CSyncs
	header_cookies_num = numberOfHeaderCookies(headers)
	tracking_keywords_in_url = trackingKeywordsInUrl(new_req_urls)
	url_str_lens = urlStringLength(new_req_urls)
	req_header_num = requestHeadersNumber(headers)
	semicolon_in_query = semicolonInQuery(req_query_strs)
	samesite_none_in_header = headerContainsSameSiteNone(headers)
	p3p_in_header = headerContainsP3P(headers)
	etag_in_header = headerContainsETag(headers)
	uuid_in_url = requestURLContainsUUID(new_req_urls)
	tracking_keywords_next_to_special_char = trackingKeywordsNextToSpecialChar(new_req_urls)
	subdomain_check = subdomainCheck(new_req_urls)
	special_char_count = specialCharCount(req_query_strs)

	# newDomainCheck(): only consider an event to be a CS if it is a request to a new domain. This will still consider google.com --> cm.g.doubleclick as a CS
	new_domain_check = newDomainCheck(old_req_urls, new_req_urls)
	query_url_check = urlInQuery(req_query_strs)
	# - - -

	# README: to add features, add feature object to this list, and add corresponding column name to redirect_column_names list above
	redirect_features_df = pd.DataFrame(list(zip(param_shared_ids, path_shared_ids, loc_header_shared_ids, redirect_id_sharing_events, url_str_lens, req_header_num, semicolon_in_query, samesite_none_in_header,\
		p3p_in_header, etag_in_header, uuid_in_url, tracking_keywords_next_to_special_char, subdomain_check,\
		special_char_count, req_query_str_lens, req_query_cookies, header_cookies_num,\
		tracking_keywords_in_url, new_domain_check, query_url_check, cookie_syncs)), columns = redirect_column_names)

	return redirect_features_df



def feature_extraction(crawl_db):
	redirect_features_df = redirect_extraction(crawl_db)
	return redirect_features_df
