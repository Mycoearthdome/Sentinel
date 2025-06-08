from .ml import SignatureClassifier
import argparse
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import cross_val_score

DEFAULT_URLS = [
    # MalwareBazaar full signature dump (zip containing CSV)
    "https://bazaar.abuse.ch/export/csv/full/"
]


def main():
    parser = argparse.ArgumentParser(description="Train signature classifier")
    parser.add_argument('--urls', nargs='*', default=DEFAULT_URLS,
                        help='CSV or ZIP URLs providing a signature dataset')
    parser.add_argument('--model-path', default='signature_model.joblib')
    parser.add_argument('--cv', type=int, default=5,
                        help='Number of cross validation folds')
    args = parser.parse_args()

    clf = SignatureClassifier()
    df = clf.fetch_dataset(args.urls)

    # Perform cross validation using a pipeline so the vectorizer is
    # fitted inside each fold. This provides a more realistic estimate
    # of model performance.
    pipeline = make_pipeline(clf.vectorizer, clf.clf)
    scores = cross_val_score(pipeline, df['signature'], df['label'],
                             cv=args.cv, scoring='f1')
    print(f"Cross-validation F1: {scores.mean():.3f} ± {scores.std():.3f}")

    # Fit on the full dataset and save the resulting model
    pipeline.fit(df['signature'], df['label'])
    clf.vectorizer = pipeline.named_steps['tfidfvectorizer']
    clf.clf = pipeline.named_steps['randomforestclassifier']
    clf.save(args.model_path)
    print(f"Model saved to {args.model_path}")


if __name__ == "__main__":
    main()
