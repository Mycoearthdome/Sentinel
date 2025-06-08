import requests
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
from io import StringIO, BytesIO
import zipfile

class SignatureClassifier:
    """Simple classifier based on string signatures."""

    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2,4))
        self.clf = RandomForestClassifier(n_estimators=100, random_state=42)

    def fetch_dataset(self, urls):
        """Download and merge CSV datasets.

        Supports plain CSV files and ZIP archives containing a single CSV
        file. If the CSV does not include a ``label`` column it is assumed to
        represent malicious samples and the label is set to ``1``.
        """
        frames = []
        for url in urls:
            if url.startswith("file://"):
                path = url[7:]
                df = pd.read_csv(path)
                if "label" not in df.columns:
                    df["label"] = 1
                frames.append(df)
                continue
            resp = requests.get(url)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "zip" in content_type or url.endswith(".zip"):
                with zipfile.ZipFile(BytesIO(resp.content)) as zf:
                    name = zf.namelist()[0]
                    with zf.open(name) as f:
                        df = pd.read_csv(f)
            else:
                df = pd.read_csv(StringIO(resp.text))
            if "label" not in df.columns:
                df["label"] = 1
            frames.append(df)
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
