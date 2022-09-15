# README: Ground Truth Labeling 
## Files
### ground_truth_runner.py
*Requires label_ground_truth.py*. 

Iterates over past crawl data databases in /crawl folder, and labels positive, negative, and unknown cookie matching instances for each crawl by calling label_ground_truth.py. 

To run `ground_truth_runner.py`: `ground_truth_runner.py [-h] --par | --no-par [--progress-bar | --no-progress-bar] [-v {0,1,2}]`

Typical usage: `ground_truth_runner.py --par`

### label_ground_truth.py
Iterates over inputted crawl database. From individual redirect rows (graph edge), labels redirect as positive, negative, or unknown. Returns these labels and their respective domains to ground_truth_runner.py. 

This file is not intended to be used directly.



## Papadapolous Cookie Synchronization Method
[Paper](https://dl.acm.org/doi/abs/10.1145/3308558.3313542?casa_token=utdQ_eFW7ToAAAAA:cVJlTJdogGREFlOumypH7XDKIDgjvFVO3kctVb4WBGbPI5p3jWtBqS-nQab8GYVrGW4jsJ6yfduN)
1. Extract all browser cookies set, via openWPM javascript_cookies table
    - Filter out session cookies (cookies without expiration date)
    - Parse cookie values using common delimiters (:, &)
2. Detect possible cookie_id sharing events in the http_redirects table 
    - Identify ID-looking strings (> 10 alphanumeric) in:
        - requested redirect parameters
        - requested redirect path
        - requested redirect location header. 
    - If this ID is seen for the first time, store in hashtable with URL's domain. If this ID has been seen before, consider it as a shared ID, and the requests carrying it as ID-sharing requests.
    - Use entity_map.json to determine organizations of domains, to discriminate between intentional ID leaking, and internal ID sharing (avoid false-positives).
3. A detected shared ID is considered a cookie sync if the shared ID matches an extracted browser cookie from the first step. 
