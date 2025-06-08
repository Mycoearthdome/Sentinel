import requests
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
from io import StringIO

class SignatureClassifier:
    """Simple classifier based on string signatures."""

    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2,4))
        self.clf = RandomForestClassifier(n_estimators=100, random_state=42)

    def fetch_dataset(self, urls):
        frames = []
        for url in urls:
            if url.startswith('file://'):
                path = url[7:]
                frames.append(pd.read_csv(path))
                continue
            resp = requests.get(url)
            resp.raise_for_status()
            frames.append(pd.read_csv(StringIO(resp.text)))
        return pd.concat(frames, ignore_index=True)

    def train(self, df):
        X = self.vectorizer.fit_transform(df['signature'])
        y = df['label']
        self.clf.fit(X, y)

    def predict(self, signatures):
        X = self.vectorizer.transform(signatures)
        return self.clf.predict_proba(X)[:, 1]

    def save(self, path):
        joblib.dump({'vectorizer': self.vectorizer, 'clf': self.clf}, path)

    def load(self, path):
        data = joblib.load(path)
        self.vectorizer = data['vectorizer']
        self.clf = data['clf']
