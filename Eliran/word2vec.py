from __future__ import absolute_import, division, print_function
# for word encoding
import codecs
# for regex
import glob
import re
# concurrency
import multiprocessing
# dealing with OS, reading files
import os
# pretty printing
import pprint
# natural language toolkit
import nltk
# word 2 vec
import gensim.models.word2vec as w2v
# dimensionality reduction
import sklearn.manifold
# math
import numpy as np
# plotting
import matplotlib.pyplot as plt
# parser
import pandas as pd
# visualization
import seaborn as sns


def sentences_to_word_list(raw):
    clean = re.sub("[^a-zA-Z]", " ", raw)
    words = clean.split()
    return words


# clean out data
nltk.download('punkt')  # pre train tokenizer
# nltk.download('stopwords')  #  words like and, the, an, a, of
# get the data

file_name = sorted(glob.glob('*.csv'))
print(file_name)
corpus_raw = u""
for file in file_name:
    with codecs.open(file, "r", "utf-8") as book_file:
        corpus_raw += book_file.read()

tokenizer = nltk.data.load('tokenizers/punkt/english.pickle')
raw_sentences = tokenizer.tokenize(corpus_raw)

print(len(raw_sentences))

sentences = []

for raw_sentence in raw_sentences:
    if (len(raw_sentence)) > 0:
        sentences.append(sentences_to_word_list(raw_sentence))

token_count = sum([len(sentence) for sentence in sentences])
print(token_count)

print("#################################Train#################################")

num_features = 300
min_word_count = 3
num_workers = multiprocessing.cpu_count()
context_size = 7
downsampling = 1e-3
seed = 1

sql2vec = w2v.Word2Vec(sg=1, seed=seed, workers=num_workers, size=num_features, min_count=min_word_count, window=context_size, sample=downsampling)
sql2vec.build_vocab(sentences)

sql2vec.train(sentences, total_examples=sql2vec.corpus_count, epochs=sql2vec.iter)
if os.path.exists("trained.w2v"):
    os.remove("trained.w2v")

sql2vec.save("trained.w2v")


import matplotlib
from sklearn import datasets, svm

digits = datasets.load_digits()

dlf = svm.SVC(gamma=0.001, C=100)

x, y = digits.data[:-1], digits.target[:-1]




