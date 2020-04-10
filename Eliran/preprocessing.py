from __future__ import absolute_import, division, print_function

# for word encoding
# for regex
# concurrency
# dealing with OS, reading files
# pretty printing
# natural language toolkit
import time
from urllib.parse import unquote

import nltk
# word 2 vec
# dimensionality reduction
# math
import numpy as np
# plotting
# parser
import pandas as pd
# visualization
import wn as wn
from sklearn import model_selection, svm
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder

print("Step A - Reading CSV")
start = time.time()
np.random.seed(500)
Corpus = pd.read_csv("payload_full_sqli.csv", encoding='latin-1')
# "payload","length","attack_type","label"
# Step - a : Remove blank rows if any.
Corpus['payload'].dropna(inplace=True)
print("\tExecute A in: "+str((time.time()-start)))
print("\t Done.")

print("Step B - Lowercase the relevant text from the data")
start = time.time()
# Step - b : Change all the text to lower case. This is required as python interprets 'dog' and 'DOG' differently
Corpus['payload'] = [entry.lower() for entry in Corpus['payload']]
print("\tExecute B in: "+str((time.time()-start)))
print("\t Done.")

print("Step C - Tokenizer the data")
start = time.time()
# Step - c : Tokenization : In this each entry in the corpus will be broken into set of words
Corpus['payload']= [nltk.word_tokenize(entry) for entry in Corpus['payload']]
print("\tExecute C in: "+str((time.time()-start)))
print("\t Done.")

print("Step D - Removing stop words, Non-numeric and perfom Word stemming/lemmenting")
start = time.time()
# Step - d : Remove Stop words, Non-Numeric and perfom Word Stemming/Lemmenting.
# WordNetLemmatizer requires Pos tags to understand if the word is noun or verb or adjective etc. By default it is set to Noun
tag_map = nltk.defaultdict(lambda : wn.NOUN)
tag_map['J'] = wn.ADJ
tag_map['V'] = wn.VERB
tag_map['R'] = wn.ADV
print("\tExecute D in: "+str((time.time()-start)))
print("\t Done.")

print("Step E - Pre-Processing the payloads")
start = time.time()
for index,entry in enumerate(Corpus['payload']):
    # Declaring Empty List to store the words that follow the rules for this step
    Final_words = []
    # Initializing WordNetLemmatizer()
    word_Lemmatized = nltk.WordNetLemmatizer()
    # pos_tag function below will provide the 'tag' i.e if the word is Noun(N) or Verb(V) or something else.
    for word, tag in nltk.pos_tag(entry):
        # Below condition is to check for Stop words and consider only alphabets
        # if word not in stopwords.words('english'):
        # if word.isalpha():
        word_Final = word_Lemmatized.lemmatize(word, tag_map[tag[0]])
        word_Final = unquote(word_Final)
        Final_words.append(word_Final)
    # The final processed set of words for each iteration will be stored in 'text_final'
    Corpus.loc[index,'payload_final'] = str(Final_words)
print("\tExecute E in: " + str(time.time() - start))
print("\t Done.")

print("Step F - Spliting data to train & test")
start = time.time()
Train_X, Test_X, Train_Y, Test_Y = model_selection.train_test_split(Corpus['payload_final'], Corpus['attack_type'], test_size=0.3)

Encoder = LabelEncoder()
Train_Y = Encoder.fit_transform(Train_Y)
Test_Y = Encoder.fit_transform(Test_Y)
print("\tExecute F in: "+str((time.time()-start)))
print("\t Done.")

print("Step G - Categorizing the Data")
start = time.time()
Tfidf_vect = TfidfVectorizer(max_features=5000)
Tfidf_vect.fit(Corpus['payload_final'])
Train_X_Tfidf = Tfidf_vect.transform(Train_X)
Test_X_Tfidf = Tfidf_vect.transform(Test_X)
print("\tExecute G in: "+str((time.time()-start)))
print("\t Done.")

print("Step H - Training Data with SVM")
start = time.time()
# Classifier - Algorithm - SVM
# fit the training dataset on the classifier
SVM = svm.SVC(C=1.0, kernel='linear', degree=300, gamma='auto')
SVM.fit(Train_X_Tfidf, Train_Y)
# predict the labels on validation dataset
print("\tExecute H in: "+str((time.time()-start)))
print("\t Done.")

print("Final Step - Predicting test data")
start = time.time()
predictions_SVM = SVM.predict(Test_X_Tfidf)
# Use accuracy_score function to get the accuracy
print("\tSVM Accuracy Score -> ",accuracy_score(predictions_SVM, Test_Y)*100)
print("\tExecute Final Step in: "+str((time.time()-start)))
print("\t Done.")

print("Testing My Data")
print("\tStep 1 - Pre-Processing the payloads")
start = time.time()
Corpus = pd.read_csv("mypayloads.csv", encoding='latin-1')
print("\t\tExecute 1 in: "+str((time.time()-start)))
print("\t\tDone.")

print("\tStep 2 - Lowercase the relevant text from the data")
start = time.time()
# Step - b : Change all the text to lower case. This is required as python interprets 'dog' and 'DOG' differently
Corpus['payload'] = [entry.lower() for entry in Corpus['payload']]
print("\t\tExecute 2 in: "+str((time.time()-start)))
print("\t\tDone.")

print("\tStep 3 - Tokenizer the data")
start = time.time()
# Step - c : Tokenization : In this each entry in the corpus will be broken into set of words
Corpus['payload']= [nltk.word_tokenize(entry) for entry in Corpus['payload']]
print("\t\tExecute C in: "+str((time.time()-start)))
print("\t\tDone.")

print("\tStep 4 - Removing stop words, Non-numeric and perfom Word stemming/lemmenting")
start = time.time()
# Step - d : Remove Stop words, Non-Numeric and perfom Word Stemming/Lemmenting.
# WordNetLemmatizer requires Pos tags to understand if the word is noun or verb or adjective etc. By default it is set to Noun
tag_map = nltk.defaultdict(lambda : wn.NOUN)
tag_map['J'] = wn.ADJ
tag_map['V'] = wn.VERB
tag_map['R'] = wn.ADV
print("\t\tExecute D in: "+str((time.time()-start)))
print("\t\tDone.")

print("\tStep 5 - Pre-Processing the payloads")
start = time.time()
for index, entry in enumerate(Corpus['payload']):
    # Declaring Empty List to store the words that follow the rules for this step
    Final_words = []
    # Initializing WordNetLemmatizer()
    word_Lemmatized = nltk.WordNetLemmatizer()
    # pos_tag function below will provide the 'tag' i.e if the word is Noun(N) or Verb(V) or something else.
    for word, tag in nltk.pos_tag(entry):
        # Below condition is to check for Stop words and consider only alphabets
        # if word not in stopwords.words('english'):
    # if word.isalpha():
        word_Final = word_Lemmatized.lemmatize(word, tag_map[tag[0]])
        word_Final = unquote(word_Final)
        Final_words.append(word_Final)
    # The final processed set of words for each iteration will be stored in 'text_final'
    Corpus.loc[index, 'payload_final'] = str(Final_words)


print("Step F - Spliting data to train & test")
start = time.time()
Encoder = LabelEncoder()
# Train_Y = Encoder.fit_transform(Corpus['payload_final'])
print("\tExecute F in: "+str((time.time()-start)))
print("\t Done.")
Test_X_Tfidf = Tfidf_vect.transform(Corpus['payload_final'])
Test_X = Encoder.fit_transform(Corpus['label'])
predictions_SVM = SVM.predict(Test_X_Tfidf)
print("Prediction len: "+str(len(predictions_SVM))+ " Data len: "+str(len(Corpus['payload_final'])))
index = 0
for index in range(0, len(Corpus['payload_final'])):
    string = Corpus['payload_final'][index]
    print("for: "+string)
    print("\tResult is "+str(predictions_SVM[index]))
print("\tSVM Accuracy Score -> ",accuracy_score(predictions_SVM, Test_X)*100)

# Encoder = LabelEncoder()
# Train_Y = Encoder.fit_transform(Train_Y)
# Test_Y = Encoder.fit_transform(Test_Y)
# print("\tExecute F in: "+str((time.time()-start)))
# print("\t Done.")
#
# print("Step G - Categorizing the Data")
# start = time.time()
# Tfidf_vect = TfidfVectorizer(max_features=5000)
# Tfidf_vect.fit(Corpus['payload_final'])
# Train_X_Tfidf = Tfidf_vect.transform(Train_X)
# Test_X_Tfidf = Tfidf_vect.transform(Test_X)
# print("\tExecute G in: "+str((time.time()-start)))

