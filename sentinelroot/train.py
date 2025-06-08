from .ml import SignatureClassifier
import argparse

DEFAULT_URLS = [
    # MalwareBazaar full signature dump (zip containing CSV)
    "https://bazaar.abuse.ch/export/csv/full/"
]


def main():
    parser = argparse.ArgumentParser(description="Train signature classifier")
    parser.add_argument('--urls', nargs='*', default=DEFAULT_URLS,
                        help='CSV or ZIP URLs providing a signature dataset')
    parser.add_argument('--model-path', default='signature_model.joblib')
    args = parser.parse_args()

    clf = SignatureClassifier()
    df = clf.fetch_dataset(args.urls)
    clf.train(df)
    clf.save(args.model_path)
    print(f"Model saved to {args.model_path}")


if __name__ == "__main__":
    main()
