import pandas as pd
import csv
import sqlite3
import tldextract
import re
import os

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

# - - - ML Features Functions
def urlStringLength(urls):
	url_str_lens = []
	for url in urls:
		i = url[1].find('?')
		url_len = len(url[1])
		if i != -1:
			split = url[1].split('?')
			url_len = len(split[0])
		url_str_lens.append(url_len)
	return url_str_lens

def queryStringLength(urls, list_2):
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

def requestHeadersNumber(headers):
	request_header_count = []
	for header in headers:
		request_header_count.append(header[1].count('[') - 1)
	return request_header_count

def semicolonInQuery(query_strs):
	semicolon_query_check = []
	for query in query_strs:
		if query != None:
			if ';' in query:
				semicolon_query_check.append(1)
			else:
				semicolon_query_check.append(0)
	return semicolon_query_check

def getQueryCookieStrings(query):
	cookie_count = 0
	if query != None:
		# find alphanumeric strings >= 14
		id_size = 0
		for char in query:
			if char.isalnum() or char == '-':
				id_size += 1
			else:
				id_size = 0
			# only increment cookie_count once per cookie_size >= 14 detection
			if id_size == 14:
				cookie_count += 1

	return cookie_count

def getHeaderCookieStrings(header_substring):
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

def numberOfQueryCookies(query_strs):
	#cid_keywords ['user_id', 'USER_ID', 'uuid', 'pid', 'cid']
	# ^ not used, another detection option

	query_cookie_count = []
	for query in query_strs:
		cookie_count = 0
		if query != None:
			cookie_count = getQueryCookieStrings(query)

		query_cookie_count.append(cookie_count)
	return query_cookie_count

def numberOfHeaderCookies(headers):
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
				cookie_count = getHeaderCookieStrings(set_cookie_substring)
		header_cookie_count.append(cookie_count)

	return header_cookie_count

def urlContainsUUID(urls):
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

def trackingKeywordsInUrl(urls):
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

def trackingKeywordsNextToSpecialChar(urls):
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

def subdomainCheck(urls):
	subdomain_check = []

	for url in urls:
		tld = tldextract.extract(url[1])
		if tld.subdomain != None and tld.subdomain != 'www':
			subdomain_check.append(1)
		else:
			subdomain_check.append(0)
	return subdomain_check

def specialCharCount(query_strs):
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

def headerContainsSameSiteNone(headers):
	same_site_none_check = []

	for header in headers:
		if "SameSite=None" in header[1] or 'samesite=none' in header[1] or 'SameSite=none' in header[1] or 'samesite=None' in header[1]:
			same_site_none_check.append(1)
		else:
			same_site_none_check.append(0)
	return same_site_none_check

def headerContainsP3P(headers):
	p3p_check = []
	for header in headers:
		if 'p3p' in header[1] or 'P3P' in header[1]:
			p3p_check.append(1)
		else:
			p3p_check.append(0)
	return p3p_check

def headerContainsETag(headers):
	etag_check = []
	for header in headers:
		if 'etag' in header[1] or 'ETag' in header[1] or 'Etag' in header[1] or 'ETAG' in header[1]:
			etag_check.append(1)
		else:
			etag_check.append(0)
	return etag_check

def requestURLContainsUUID(urls):
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
# - - -

# - - - CS Labeling Functions
def urlInQuery(req_query_strs):
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

def SOTACookieSync(url_in_query, req_query_cookies, new_domain_check):
	sota_cookie_sync_check = []

	i = 0
	for query_cookie in req_query_cookies:
		if not new_domain_check[i]:
			sota_cookie_sync_check.append(0)
		elif query_cookie > 0 and url_in_query[i]:
			sota_cookie_sync_check.append(1)
		else:
			sota_cookie_sync_check.append(0)
		i += 1
	return sota_cookie_sync_check

referrer_keywords = ['refUrl', 'refurl', 'refURL', 'redir', 'redirect', 'refer', 'referrer',\
'ref', 'siteID', 'site_id', 'site_ID', 'publisher', 'nw', 'ex', 'partner', 'receive', 'rurl']

def getHeaderQueries(headers):
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

def headerDomainShared(headers):
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

def getTopLevelUrl(site_urls, header):
	if len(site_urls) == 1:
		return site_urls[0][1]
	visit_id = header[0]

	for url in site_urls:
		if url[0] == visit_id:
			return url[1]


def	domainOrURLInHeader(headers, site_urls):
	header_domain_shared = []

	# extract header URL queries
	header_queries = getHeaderQueries(headers)
	header_query_urls = urlInQuery(header_queries)

	# checks for policyref in p3p header and domain in set-cookie header
	header_domain_shared = headerDomainShared(headers)

	i = 0
	for header in headers:
		keyword_found = False
		top_level_url = getTopLevelUrl(site_urls, header)
		tld = tldextract.extract(top_level_url)

		if header[1] != None:
			# check URL shared in query
			if header_query_urls[i] != None:
				header_domain_shared.append(1)
				i += 1
				continue
			# check domain or top_level_url shared anywhere
			elif tld.domain in header[1] or top_level_url in header[1]:
				header_domain_shared.append(1)
				i += 1
				continue
			elif header_domain_shared[i]:
				header_domain_shared.append(1)
				i += 1
				continue
			# to detect hashed urls or domains
			for keyword in referrer_keywords:
				if keyword in header[1]:
					keyword_found = True
					break
			if keyword_found:
				header_domain_shared.append(1)
			else:
				header_domain_shared.append(0)
		i += 1
	return header_domain_shared

def domainOrUrlInQuery(req_query_strs, new_req_urls, site_urls):
	query_domain_shared = []

	i = 0
	for query in req_query_strs:
		if query != None:
			keyword_found = False
			top_level_url = getTopLevelUrl(site_urls, new_req_urls[i])
			tld = tldextract.extract(top_level_url)

			regex = r"(?i)\b(([.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
			if len(re.findall(regex, query)) > 0:
				query_domain_shared.append(1)
				i += 1
				continue
			if tld.domain in query or top_level_url in query:
				query_domain_shared.append(1)
				i += 1
				continue
			# to detect hashed urls or domains
			for keyword in referrer_keywords:
				if keyword in query:
					keyword_found = True
					break
			if keyword_found:
				query_domain_shared.append(1)
			else:
				query_domain_shared.append(0)
		else:
			query_domain_shared.append(0)
		i += 1
	return query_domain_shared

def expansionCookieSync(req_query_cookies, header_cookies, header_domain_shared, query_domain_shared, new_domain_check):
	# check cookie shared
	cookie_shared = []
	domain_or_url_shared = []

	i = 0
	for cookie in req_query_cookies:
		if cookie or header_cookies[i]:
			cookie_shared.append(1)
		else:
			cookie_shared.append(0)
		i += 1
	i = 0
	for domain_shared in query_domain_shared:
		if domain_shared or header_domain_shared[i]:
			domain_or_url_shared.append(1)
		else:
			domain_or_url_shared.append(0)
		i += 1
	cs_check = []
	i = 0
	for domain in domain_or_url_shared:
		if not new_domain_check[i]:
			cs_check.append(0)
		elif domain and cookie_shared[i]:
			cs_check.append(1)
		else:
			cs_check.append(0)
		i += 1

	return cs_check

def expansionCookieSync_andTrackingKeywords(req_query_cookies, header_cookies, header_domain_shared, query_domain_shared, tracking_keywords_in_url, new_domain_check):
	# check cookie shared
	cookie_shared = []
	domain_or_url_shared = []

	i = 0
	for cookie in req_query_cookies:
		if cookie or header_cookies[i]:
			cookie_shared.append(1)
		else:
			cookie_shared.append(0)
		i += 1
	i = 0
	for domain_shared in query_domain_shared:
		if domain_shared or header_domain_shared[i]:
			domain_or_url_shared.append(1)
		else:
			domain_or_url_shared.append(0)
		i += 1
	cs_check = []
	i = 0
	for domain in domain_or_url_shared:
		if not new_domain_check[i]:
			cs_check.append(0)
		elif domain and cookie_shared[i]:
			cs_check.append(1)
		else:
			cs_check.append(0)
		i += 1

	i = 0
	while i < len(cs_check):
		if not cs_check[i]:
			if tracking_keywords_in_url[i] and cookie_shared[i]:
				cs_check[i] = 1
		i += 1

	return cs_check

def newDomainCheck(old_req_urls, new_req_urls):
	domain_check = []

	i = 0
	for referrer in old_req_urls:
		tld_ref = tldextract.extract(referrer[1])
		tld_req = tldextract.extract(new_req_urls[i][1])

		if tld_ref.domain == tld_req.domain and tld_ref.suffix == tld_req.suffix:
			domain_check.append(0)
		else:
			domain_check.append(1)
		i += 1
	return domain_check

def redirectLabel(new_req_urls):
	redirect_label = []
	for url in new_req_urls:
		redirect_label.append(1)
	return redirect_label

def requestLabel(new_req_urls):
	request_label = []
	for url in new_req_urls:
		request_label.append(0)
	return request_label

redirect_column_names = ['request_or_redirect', 'url_str_lens', 'req_header_num', 'semicolon_in_query', 'samesite_none_in_header',\
	'p3p_in_header', 'etag_in_header', 'uuid_in_url', 'tracking_keywords_next_to_special_char', 'subdomain_check',\
	'special_char_count', 'req_query_str_lens', 'req_query_cookies', 'header_cookies',\
	'tracking_keywords_in_url', 'new_domain_check', 'query_url_check', 'header_domain_shared', 'query_domain_shared', 'sota_cs',\
	'expansion_cs', 'expansion_cs_and_tracking_keywords']



def redirect_extraction(crawl_db):
	# README: only using top 100 sites + 8 case study crawls for alpha testing. Will adjust implementation to handle whole dataset when it is ready

	# - - - load database and features
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

	connection.close()
	# - - -
	# redirects = 1
	request_or_redirect = redirectLabel(new_req_urls)

	# - - - Primary Features: features needed to label all definitions of CS

	# README (This cookie_id definition may need to be adjusted): Cookie IDs are defined as alphanumeric strings >= 14 chars
	# This was determined after trial and error to minimize false positives. 13 chars and below started to pick up urls with long domain names, while 14 does not
	req_query_str_lens, req_query_strs = queryStringLength(new_req_urls)
	print(req_query_str_lens)
	req_query_cookies = numberOfQueryCookies(req_query_strs)
	header_cookies = numberOfHeaderCookies(headers)
	tracking_keywords_in_url = trackingKeywordsInUrl(new_req_urls)
	# - - -

	# - - - Secondary Features: features to be used only for ML classifier. Not needed to label CSyncs
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
	# - - -

	#### Step 1 - State of The Art (SOTA) classification technique - url and cid shared in url query

	# newDomainCheck(): only consider an event to be a CS if it is a request to a new domain. This will still consider google.com --> cm.g.doubleclick as a CS
	new_domain_check = newDomainCheck(old_req_urls, new_req_urls)
	query_url_check = urlInQuery(req_query_strs)
	sota_cs = SOTACookieSync(query_url_check, req_query_cookies, new_domain_check)
	#print("SOTA:", sum(sota_cs))

	#### Step 2 - Gunrock Breakerspace Expanded CS Definition - Includes Direct Primary / Secondary CS Features.
	# Considers a CS to be any redirect where the (url or domain) + cookie_ID is shared in URL or header
	header_domain_shared = domainOrURLInHeader(headers, site_urls)
	query_domain_shared = domainOrUrlInQuery(req_query_strs, new_req_urls, site_urls)
	expansion_cs = expansionCookieSync(req_query_cookies, header_cookies, header_domain_shared, query_domain_shared, new_domain_check)
	#print("Expansion features:", sum(expansion_cs))

	#### NOT FINALIZED, JUST A STARTING POINT - Step 2 (alternate definition): includes all cases as above, and also considers a CS if (cookie_ID shared + tracker keyword in URL)
	expansion_cs_and_tracking_keywords = expansionCookieSync_andTrackingKeywords(req_query_cookies, header_cookies, header_domain_shared, query_domain_shared, tracking_keywords_in_url, new_domain_check)
	#print("Expansion features + tracking keywords:", sum(expansion_cs_and_tracking_keywords))


	redirect_features_df = pd.DataFrame(list(zip(request_or_redirect, url_str_lens, req_header_num, semicolon_in_query, samesite_none_in_header,\
		p3p_in_header, etag_in_header, uuid_in_url, tracking_keywords_next_to_special_char, subdomain_check,\
		special_char_count, req_query_str_lens, req_query_cookies, header_cookies,\
		tracking_keywords_in_url, new_domain_check, query_url_check, header_domain_shared, query_domain_shared, sota_cs,\
		expansion_cs, expansion_cs_and_tracking_keywords)), columns = redirect_column_names)

	return redirect_features_df

request_column_names = ['request_or_redirect', 'url_str_lens', 'req_header_num', 'semicolon_in_query', 'samesite_none_in_header',\
	'p3p_in_header', 'etag_in_header', 'uuid_in_url', 'tracking_keywords_next_to_special_char', 'subdomain_check',\
	'special_char_count', 'req_query_str_lens', 'req_query_cookies', 'header_cookies',\
	'tracking_keywords_in_url', 'new_domain_check', 'query_url_check', 'header_domain_shared', 'query_domain_shared', 'sota_cs',\
	'expansion_cs', 'expansion_cs_and_tracking_keywords']

def request_extraction(crawl_db):
	# README: only using top 100 sites + 8 case study crawls for alpha testing. Will adjust implementation to handle whole dataset when it is ready

	# - - - load database and features
	connection = sqlite3.connect(crawl_db)
	cursor = connection.cursor()

	cursor.execute("SELECT visit_id, url FROM http_requests")
	new_req_urls = cursor.fetchall()

	cursor.execute("SELECT visit_id, referrer FROM http_requests")
	referrers = cursor.fetchall()

	#cursor.execute("SELECT response_status FROM http_requests")
	# add to list
	#response_codes = cursor.fetchall()

	cursor.execute("SELECT visit_id, headers FROM http_requests")
	headers = cursor.fetchall()

	cursor.execute("SELECT visit_id, site_url FROM site_visits")
	site_urls = cursor.fetchall()

	cursor.execute("SELECT id FROM http_requests")
	id = cursor.fetchall()
	print(id[-1])

	connection.close()
	# - - -

	# requests = 0
	request_or_redirect = requestLabel(new_req_urls)

	# - - - Primary Features: features needed to label all definitions of CS

	# README (This cookie_id definition may need to be adjusted): Cookie IDs are defined as alphanumeric strings >= 14 chars
	# This was determined after trial and error to minimize false positives. 13 chars and below started to pick up urls with long domain names, while 14 does not
	req_query_str_lens, req_query_strs = queryStringLength(new_req_urls)
	req_query_cookies = numberOfQueryCookies(req_query_strs)
	header_cookies = numberOfHeaderCookies(headers)
	tracking_keywords_in_url = trackingKeywordsInUrl(new_req_urls)
	# - - -

	# - - - Secondary Features: features to be used only for ML classifier. Not needed to label CSyncs
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
	# - - -

	#### Step 1 - State of The Art (SOTA) classification technique - url and cid shared in url query

	# newDomainCheck(): only consider an event to be a CS if it is a request to a new domain. This will still consider google.com --> cm.g.doubleclick as a CS
	new_domain_check = newDomainCheck(referrers, new_req_urls)
	query_url_check = urlInQuery(req_query_strs)
	sota_cs = SOTACookieSync(query_url_check, req_query_cookies, new_domain_check)
	print("SOTA:", sum(sota_cs))

	#### Step 2 - Gunrock Breakerspace Expanded CS Definition - Includes Direct Primary / Secondary CS Features.
	# Considers a CS to be any redirect where the (url or domain) + cookie_ID is shared in URL or header
	header_domain_shared = domainOrURLInHeader(headers, site_urls)
	query_domain_shared = domainOrUrlInQuery(req_query_strs, new_req_urls, site_urls)
	expansion_cs = expansionCookieSync(req_query_cookies, header_cookies, header_domain_shared, query_domain_shared, new_domain_check)
	print("Expansion features:", sum(expansion_cs))

	#### NOT FINALIZED, JUST A STARTING POINT - Step 2 (alternate definition): includes all cases as above, and also considers a CS if (cookie_ID shared + tracker keyword in URL)
	expansion_cs_and_tracking_keywords = expansionCookieSync_andTrackingKeywords(req_query_cookies, header_cookies, header_domain_shared, query_domain_shared, tracking_keywords_in_url, new_domain_check)
	print("Expansion features + tracking keywords:", sum(expansion_cs_and_tracking_keywords))


	request_features_df = pd.DataFrame(list(zip(request_or_redirect, url_str_lens, req_header_num, semicolon_in_query, samesite_none_in_header,\
		p3p_in_header, etag_in_header, uuid_in_url, tracking_keywords_next_to_special_char, subdomain_check,\
		special_char_count, req_query_str_lens, req_query_cookies, header_cookies,\
		tracking_keywords_in_url, new_domain_check, query_url_check, header_domain_shared, query_domain_shared, sota_cs,\
		expansion_cs, expansion_cs_and_tracking_keywords)), columns = request_column_names)

	return request_features_df

def feature_extraction(crawl_db):
	redirect_features_df = redirect_extraction(crawl_db)
	#request_features_df = request_extraction(crawl_db)
	return redirect_features_df
	#return request_features_df.append(redirect_features_df)
