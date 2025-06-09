import requests
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:  # pragma: no cover - optional dependency
    HAS_XGB = False
import joblib
from io import StringIO, BytesIO
import zipfile

class SignatureClassifier:
    """Simple classifier based on string signatures."""

    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2,4))
        self.clf = RandomForestClassifier(n_estimators=100, random_state=42)

    def _parse_csv(self, text):
        """Parse CSV text while respecting comment lines.

        The MalwareBazaar dataset used by default starts with ``#`` comments and
        the header is included in one of those commented lines. ``pandas`` does
        not handle this situation well if we simply pass ``comment='#'`` because
        it would treat the first row of actual data as the header. This helper
        extracts the header manually and then parses the remaining CSV content.
        """
        header = None
        lines = []
        for line in text.splitlines():
            if line.startswith('#'):
                if header is None and 'first_seen_utc' in line:
                    header = line.lstrip('#').strip()
                continue
            lines.append(line)
        if header:
            columns = [c.strip(' "') for c in header.split(',')]
            return pd.read_csv(StringIO('\n'.join(lines)), names=columns,
                               quotechar='"', skipinitialspace=True)
        return pd.read_csv(StringIO(text))

    def fetch_dataset(self, urls):
        """Download and merge CSV datasets.

        Supports plain CSV files and ZIP archives containing a single CSV file.
        If the CSV does not include a ``label`` column it is assumed to
        represent malicious samples and the label is set to ``1``.
        """
        frames = []
        for url in urls:
            if url.startswith("file://"):
                path = url[7:]
                with open(path, 'r', encoding='utf-8') as f:
                    df = self._parse_csv(f.read())
                if "label" not in df.columns:
                    df["label"] = 1
                df = df.dropna(subset=["signature"]).reset_index(drop=True)
                frames.append(df)
                continue

            resp = requests.get(url)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "zip" in content_type or url.endswith(".zip"):
                with zipfile.ZipFile(BytesIO(resp.content)) as zf:
                    name = zf.namelist()[0]
                    with zf.open(name) as f:
                        text = f.read().decode('utf-8', errors='replace')
            else:
                text = resp.text

            df = self._parse_csv(text)
            if "label" not in df.columns:
                df["label"] = 1
            df = df.dropna(subset=["signature"]).reset_index(drop=True)
            frames.append(df)

        return pd.concat(frames, ignore_index=True)

    def train(self, df):
        X = self.vectorizer.fit_transform(df['signature'])
        y = df['label']
        self.clf.fit(X, y)

    def _positive_index(self):
        """Return probability column index for the positive class."""
        try:
            classes = list(self.clf.classes_)
            if 1 in classes:
                return classes.index(1)
        except Exception:
            pass
        return 1

    def predict(self, signatures):
        X = self.vectorizer.transform(signatures)
        probs = self.clf.predict_proba(X)
        idx = self._positive_index()
        idx = min(idx, probs.shape[1] - 1)
        return probs[:, idx]

    def save(self, path):
        joblib.dump({'vectorizer': self.vectorizer, 'clf': self.clf}, path)

    def load(self, path):
        data = joblib.load(path)
        self.vectorizer = data['vectorizer']
        self.clf = data['clf']


class StaticFeatureClassifier:
    """Classifier for static binary features using gradient boosting."""

    def __init__(self):
        if HAS_XGB:
            self.clf = XGBClassifier(use_label_encoder=False, eval_metric='logloss')
        else:
            self.clf = GradientBoostingClassifier()

    def train(self, X, y):
        self.clf.fit(X, y)

    def _positive_index(self):
        try:
            classes = list(self.clf.classes_)
            if 1 in classes:
                return classes.index(1)
        except Exception:
            pass
        return 1

    def predict(self, X):
        probs = self.clf.predict_proba(X)
        idx = self._positive_index()
        idx = min(idx, probs.shape[1] - 1)
        return probs[:, idx]

    def save(self, path):
        joblib.dump(self.clf, path)

    def load(self, path):
        self.clf = joblib.load(path)
