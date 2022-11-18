import pandas as pd
import json
import networkx as nx
import numpy as np
import os


def makeLabelDict():
    label_json = open(r'final_labels.json')
    label_map = json.load(label_json)
    labels = {}

    for resource, label in label_map.items():
        domain = resource
        labels[domain] = label
    label_json.close()
    return labels
    
if __name__ == '__main__':
    # load df
    raw_edges = pd.read_csv(r'all_edges.csv')
    # rename columns
    raw_edges.columns = ['src', 'dest']

    # remove protocol substring
    raw_edges['src'] = raw_edges['src'].replace(regex=r'https://', value='')
    raw_edges['src'] = raw_edges['src'].replace(regex=r'http://', value='')
    raw_edges['dest'] = raw_edges['dest'].replace(regex=r'https://', value='')
    raw_edges['dest'] = raw_edges['dest'].replace(regex=r'http://', value='')

    # make graph object
    Gtype = nx.MultiDiGraph()
    G = nx.from_pandas_edgelist(raw_edges, source='src', target='dest', create_using=Gtype)
    
    # make mapping of known endpoints --> labels
    labels = makeLabelDict()

    # output graph features df
    #print(G.number_of_edges())
    #print(G.number_of_nodes())

    df = pd.DataFrame.from_dict(G.nodes)
    
    # initialize features 
    df['label'] = None
    df['deg_centrality'] = None
    df['in_deg'] = None
    df['out_deg'] = None
    df['pagerank'] = None 

    # possible future features
    #df['cliques'] = None --> is_in_clique?
    #df['is_strongly_connected'] = None --> is_in_strong_connect_component?
    #df['neighbor_pos'] = None --> is_neighbor_cookie_syncing?
    #df['2nd_neighbor_pos'] = None 
    # dominating set - in/not in dominating set
    # strongly connected nodes - in/not in strongly connected components
    # strong_connect = nx.strongly_connected_components(G)

    # degree centrality
    centrality = nx.degree_centrality(G)
    in_deg_centr = nx.in_degree_centrality(G)
    out_deg_centr = nx.out_degree_centrality(G)

    # PageRank
    pagerank = nx.pagerank(G)    
    
    for index, row in df.iterrows():
        domain = row[0]
        try: # not all domains are labeled 
            df.iloc[index]['label'] = labels[domain]
            df.iloc[index]['deg_centrality'] = centrality[domain]
            df.iloc[index]['in_deg'] = in_deg_centr[domain] 
            df.iloc[index]['out_deg'] = out_deg_centr[domain] 
            df.iloc[index]['pagerank'] = pagerank[domain] 
        except KeyError:
            pass

    if os.path.exists("graph_features.csv"):
        os.remove("graph_features.csv")
    output_csv = df.to_csv('graph_features.csv', index=True, index_label=True)
