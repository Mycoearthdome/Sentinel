from .ml import SignatureClassifier
import argparse

DEFAULT_URLS = [
    # Replace these URLs with actual signature datasets
    "https://example.com/signatures.csv"
]


def main():
    parser = argparse.ArgumentParser(description="Train signature classifier")
    parser.add_argument('--urls', nargs='*', default=DEFAULT_URLS,
                        help='CSV URLs with columns signature,label')
    parser.add_argument('--model-path', default='signature_model.joblib')
    args = parser.parse_args()

    clf = SignatureClassifier()
    df = clf.fetch_dataset(args.urls)
    clf.train(df)
    clf.save(args.model_path)
    print(f"Model saved to {args.model_path}")


if __name__ == "__main__":
    main()
