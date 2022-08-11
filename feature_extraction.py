import os
from feature_tools import *

# README: Runs feature_tools.py

if __name__ == '__main__':
	db_df_list = []
	for filename in os.listdir('crawls'):
		crawl_db = os.path.join('crawls', filename)
		if os.path.isfile(crawl_db):
			crawl_df = feature_extraction(crawl_db)
			db_df_list.append(crawl_df)
		print(filename, "completed")
	df_final = pd.concat(db_df_list)

	if os.path.exists('classifier_features_dataset.csv'):
		os.remove('classifier_features_dataset.csv')
	final_csv = df_final.to_csv(path_or_buf='classifier_features_dataset.csv')
