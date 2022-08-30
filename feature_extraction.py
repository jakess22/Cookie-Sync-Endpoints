import argparse
import os
from feature_tools import *


def makeEntityHash() -> dict[str, str]:
    """
    Create hash of (eTLD+1, organization) to create O(1) entity lookup in findEntity()
    :returns: dict where key is eTLD and value is organization
    """
    entity_hash = {}

    with open("entity_map.json") as entity_json:
        entity_map = json.load(entity_json)

    for entity in entity_map:
        for property in entity_map[entity]["properties"]:
            prop_tld = tldextract.extract(property)
            tld_plus_one = prop_tld.domain + "." + prop_tld.suffix  # eTLD+1
            entity_hash[tld_plus_one] = entity
    return entity_hash


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
    entity_hash = makeEntityHash()
    db_df_list = []
    for filename in os.listdir("crawls"):
        crawl_db = os.path.join("crawls", filename)
        if os.path.isfile(crawl_db):
            print("Extracting features from", filename)
            crawl_df = feature_extraction(
                crawl_db,
                args.parallelize,
                args.progress_bar,
                args.verbose,
                None,
                entity_hash,
            )
            db_df_list.append(crawl_df)
        print()
        print(filename, "completed")
        print("- - - - - - - - -\n")
    df_final = pd.concat(db_df_list)

    final_csv = df_final.to_csv("classifier_features_dataset.csv")
