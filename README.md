# README: Feature Tool Creation 
feature_extraction.py: *Only file to be directly run*. Iterates over past crawl data databases in /crawl folder, and extracts features for each crawl by calling feature_tools.py. Outputs "classifier_features_dataset.csv" with all crawl feature data consolidated. Will override any existing file named "classifier_features_dataset.csv".

feature_tools.py: iterates over inputted crawl database and extracts individual redirect row (graph edge) features. Returns a pandas.DataFrame to feature_extraction.py. 

To Add Feature Tools in feature_tools.py:
1. In the SQL Data Extraction section of redirect_extraction(), ensure the SQL database column your function requires is loaded.
2. Write the function in feature_tools.py.
3. Have the function return a list.
4. Add the feature object name to the “redirect_column_names” list as a string (the position before 'sota_cs' is suggested).
5. Add the feature object name to the “redirect_features_df” list(zip()) in the same place as the name in the column name list (the position before 'sota_cs' is suggested).
