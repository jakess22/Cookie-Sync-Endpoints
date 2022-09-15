import argparse
import os
from label_ground_truth import *


def makeEntityDict():
    """Create dict of (eTLD+1, organization) to create O(1) entity lookup in findEntity()"""
    entity_dict = {}

    entity_json = open("entity_map.json")
    entity_map = json.load(entity_json)

    for entity in entity_map:
        for property in entity_map[entity]["properties"]:
            prop_tld = tldextract.extract(property)
            tld_plus_one = prop_tld.domain + "." + prop_tld.suffix  # eTLD+1
            entity_dict[tld_plus_one] = entity
    entity_json.close()
    return entity_dict


def updateEndpointCSDict(endpoint_cs_dict: dict(), new_endpoint_cs_count: dict()):
    for new_endpoint in new_endpoint_cs_count:
        if new_endpoint in endpoint_cs_dict:
            endpoint_cs_dict[new_endpoint] += new_endpoint_cs_count[new_endpoint]
        else:
            endpoint_cs_dict[new_endpoint] = new_endpoint_cs_count[new_endpoint]

    return endpoint_cs_dict


def create_arguement_parser() -> argparse.ArgumentParser:
    """
    Creates the feature extraction arguement parser
    :returns: a feature extraction arguement parser
    """
    parser = argparse.ArgumentParser(
        description='Script to iterate over past crawl data databases in /crawl folder, and extract features for each crawl by calling feature_tools.py. Outputs "classifier_features_dataset.csv" with all crawl feature data consolidated. Will override any existing file named "classifier_features_dataset.csv".',
    )
    parser.add_argument(
        "--par",
        dest="parallelize",
        action=argparse.BooleanOptionalAction,
        type=bool,
        required=True,
        help="Whether or not to parallelize",
    )
    parser.add_argument(
        "--progress-bar",
        dest="progress_bar",
        default=True,
        action=argparse.BooleanOptionalAction,
        type=bool,
        help="Whether or not to display progress bar",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        default=1,
        choices=[0, 1, 2],
        dest="verbose",
        type=int,
        help="Verbosity of logs.\n0: don't display logs\n1: display only warning logs\n2: display all logs\n(default: 1)",
    )
    return parser


# README: Runs feature_tools.py
if __name__ == "__main__":
    parser = create_arguement_parser()
    args = parser.parse_args()
    entity_dict = makeEntityDict()
    endpoint_cs_dict = {}
    user_cookies = []
    db_df_list = []
    for filename in os.listdir("crawls"):
        crawl_db = os.path.join("crawls", filename)
        if os.path.isfile(crawl_db):
            print("Extracting features from", filename)
            crawl_df, new_endpoint_cs_count, crawl_user_cookies = feature_extraction(
                crawl_db,
                args.parallelize,
                args.progress_bar,
                args.verbose,
                None,
                entity_dict,
            )
            db_df_list.append(crawl_df)

            endpoint_cs_dict = updateEndpointCSDict(
                endpoint_cs_dict, new_endpoint_cs_count
            )
            for cookie in crawl_user_cookies:
                user_cookies.append(cookie)
        print()
        print(filename, "completed")
        print("- - - - - - - - -\n")
    print("All crawl file features successfully extracted.")
    print("Statistics for all crawls extracted:")
    print(len(user_cookies), "HTTP and JavaScript cookies extracted.")
    cs_count = 0
    for x in endpoint_cs_dict:
        cs_count += endpoint_cs_dict[x]
    print(cs_count, "total CSyncs labelled.")

    # to be uncommented out when Kev's features are complete, or implemented in another script

    # df_final = pd.concat(db_df_list)
    # final_csv = df_final.to_csv("classifier_features_dataset.csv")
    # if os.path.exists("classifier_features_dataset.csv"):
    #    os.remove("classifier_features_dataset.csv")
    # final_csv = df_final.to_csv(path_or_buf="classifier_features_dataset.csv")
