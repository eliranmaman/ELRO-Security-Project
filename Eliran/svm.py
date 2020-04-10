import os
import re

import sklearn
from sklearn import svm
import numpy as np
import pandas as pd
from sklearn.manifold import TSNE
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import gensim.models.word2vec as w2v

sql2vec = w2v.Word2Vec.load(os.path.join("trained.w2v"))

iris = pd.read_csv('payload_train.csv')


X = iris[['payload']].values
Y = iris[['attack_type']].values

# for i in X:
#     clean = re.sub("[^a-zA-Z=!-(]", " ", i)
#     words = clean.split()
#     sum=0
#     for w in words:
#         sum += sql2vec.wv.word_vec(w)
#     i = sum
# print(X)

label_encoder = LabelEncoder()
Y = label_encoder.fit_transform(Y)
X = label_encoder.fit_transform(X)

X_train , X_test, y_train, y_test = train_test_split(X, Y)

clf = SVC(C=1.0, kernel='rbf').fit(X_train, y_train)
