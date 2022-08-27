import os
import sys
from feature_tools import *

"""Create hash of (eTLD+1, organization) to create O(1) entity lookup in findEntity()"""


def makeEntityHash():
    entity_hash = {}

    entity_json = open("entity_map.json")
    entity_map = json.load(entity_json)

    for entity in entity_map:
        for property in entity_map[entity]["properties"]:
            prop_tld = tldextract.extract(property)
            tld_plus_one = prop_tld.domain + "." + prop_tld.suffix  # eTLD+1
            entity_hash[tld_plus_one] = entity
    entity_json.close()
    return entity_hash


# README: Runs feature_tools.py
if __name__ == "__main__":
    # read in parallelization parameters
    parallelize = False
    # parallelization parameters
    progress_bar = True
    verbose = 1
    # Pandarellel documentation: "If user_memory set to None and if memory file system is available,
    # pandarallel will use it to transfer data between the main process and workers.
    # If memory file system is not available, pandarallel will default on multiprocessing data transfer (pipe).""
    use_memory_fs = None  #
    if len(sys.argv) > 1:  # if parallelization parameters are inputted
        if sys.argv[1] == "yes_par":
            parallelize = True
            if len(sys.argv) > 2:  # custom parameters
                progress_bar = sys.argv[2]
                verbose = sys.argv[3]
                use_memory_fs = sys.argv[4]
            # else, default parameters
        elif sys.argv[1] == "no_par":
            progress_bar = False
            verbose = 0
            use_memory_fs = False
    else:
        print("Command line args ERROR: Please enter a parallelization preference:")
        print(
            "[no_par: do not parallelize], [yes_par + no parameters: parallelize with default parameters], [yes_par + 4 parameters: parallelize with custom parameters]"
        )
        print("parameters in order:")
        print("(display progress bar [true/false])")
        print(
            "(verbose [0: don't display logs, 1: display only warning logs, 2: display all logs])"
        )
        print(
            "(memory file system: [None: use if available, True: use, False: use multiprocessing data transfer (pipe) instead])"
        )
        print(
            "\ndefault parameters: progress_bar = true, verbose = 1, user_memory = None"
        )
        quit()

    entity_hash = makeEntityHash()
    db_df_list = []
    for filename in os.listdir("crawls"):
        crawl_db = os.path.join("crawls", filename)
        if os.path.isfile(crawl_db):
            print("Extracting features from", filename)
            crawl_df = feature_extraction(
                crawl_db, parallelize, progress_bar, verbose, use_memory_fs, entity_hash
            )
            db_df_list.append(crawl_df)
        print()
        print(filename, "completed")
        print("- - - - - - - - -\n")
    df_final = pd.concat(db_df_list)

    if os.path.exists("classifier_features_dataset.csv"):
        os.remove("classifier_features_dataset.csv")
    final_csv = df_final.to_csv(path_or_buf="classifier_features_dataset.csv")
