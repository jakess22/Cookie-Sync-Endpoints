# README: Feature Tool Creation 
feature_extraction.py: *Runs feature_tools.py*. Iterates over past crawl data databases in /crawl folder, and extracts features for each crawl by calling feature_tools.py. Outputs "classifier_features_dataset.csv" with all crawl feature data consolidated. Will override any existing file named "classifier_features_dataset.csv".

feature_tools.py: iterates over inputted crawl database and extracts individual redirect row (graph edge) features. Returns a pandas.DataFrame to feature_extraction.py. 

To Add Feature Tools in feature_tools.py:
1. In the SQL Data Extraction section of redirect_extraction(), ensure the SQL database column your function requires is loaded.
2. Write the function in feature_tools.py.
3. Have the function return a list.
4. Add the feature object name to the “redirect_column_names” list as a string (the position before 'sota_cs' is suggested).
5. Add the feature object name to the “redirect_features_df” list(zip()) in the same place as the name in the column name list (the position before 'cookie_sync' is suggested).

Papadapolous Cookie Synchronization Method:
1. Extract all browser cookies set, via openWPM javascript_cookies table
    - Filter out session cookies (cookies without expiration date)
    - Parse cookie values using common delimiters (:, &)
2. Detect possible cookie_id sharing events in the http_redirects table 
    - Identify ID-looking strings (> 10 alphanumeric) in (i) requested redirect parameters, (ii) requested redirect path, (iii) reqested redirect location
    header. 
    - If this ID is seen for the first time, store in hashtable with URL's domain. If this ID has been seen before, consider it as a shared ID, and the   
    requests carrying it as ID-sharing requests.
    - Use entity_map.json to determine organizations of domains, to discriminate between intentional ID leaking, and internal ID sharing (avoid false-  
    positives).
3. A detected shared ID is considered a cookie sync if the shared ID matches an extracted browser cookie from the first step. 
