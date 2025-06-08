from .ml import SignatureClassifier, StaticFeatureClassifier
from .db import init_signature_db, SIGNATURE_DB
import argparse
import pandas as pd
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import cross_val_score

DEFAULT_URLS = [
    # MalwareBazaar full signature dump (zip containing CSV)
    "https://bazaar.abuse.ch/export/csv/full/"
]


def train_models(urls=DEFAULT_URLS, model_path='signature_model.joblib',
                 binary_dataset=None, cv=5):
    """Train the ML models and store them on disk."""
    clf = SignatureClassifier()
    df = clf.fetch_dataset(urls)

    # Store signatures in SQLite for faster lookup by the main heuristic
    with init_signature_db(SIGNATURE_DB) as conn:
        cur = conn.cursor()
        for sig in df['signature']:
            cur.execute(
                "INSERT OR IGNORE INTO signatures(signature) VALUES (?)", (sig,)
            )
        conn.commit()

    pipeline = make_pipeline(clf.vectorizer, clf.clf)
    scores = cross_val_score(pipeline, df['signature'], df['label'],
                             cv=cv, scoring='f1')
    print(f"Cross-validation F1: {scores.mean():.3f} ± {scores.std():.3f}")

    pipeline.fit(df['signature'], df['label'])
    clf.vectorizer = pipeline.named_steps['tfidfvectorizer']
    clf.clf = pipeline.named_steps['randomforestclassifier']
    clf.save(model_path)
    print(f"Model saved to {model_path}")

    if binary_dataset:
        bdf = pd.read_csv(binary_dataset)
        X = bdf.drop('label', axis=1)
        y = bdf['label']
        s_clf = StaticFeatureClassifier()
        scores = cross_val_score(s_clf.clf, X, y, cv=cv, scoring='f1')
        print(f"Static features F1: {scores.mean():.3f} ± {scores.std():.3f}")
        s_clf.train(X, y)
        s_clf.save('static_model.joblib')
        print("Static model saved to static_model.joblib")


def main():
    parser = argparse.ArgumentParser(description="Train signature classifier")
    parser.add_argument('--urls', nargs='*', default=DEFAULT_URLS,
                        help='CSV or ZIP URLs providing a signature dataset')
    parser.add_argument('--model-path', default='signature_model.joblib')
    parser.add_argument('--binary-dataset', help='CSV of extracted binary features for XGBoost model')
    parser.add_argument('--cv', type=int, default=5,
                        help='Number of cross validation folds')
    args = parser.parse_args()

    train_models(
        urls=args.urls,
        model_path=args.model_path,
        binary_dataset=args.binary_dataset,
        cv=args.cv,
    )


if __name__ == "__main__":
    main()
