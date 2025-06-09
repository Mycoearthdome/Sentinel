from pathlib import Path
from setuptools import setup, find_packages

README = Path(__file__).with_name("README.md").read_text(encoding="utf-8")

setup(
    name="sentinelroot",
    version="0.1.0",
    description="SentinelRoot heuristic monitoring tools",
    long_description=README,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={"sentinelroot": ["malicious_ips.json"]},
    python_requires=">=3.7",
    install_requires=[
        "psutil>=5.9",
        "requests",
        "pandas",
        "scikit-learn",
        "xgboost",
        "lief",
    ],
    entry_points={
        "console_scripts": [
            "sentinelroot=sentinelroot.sentinel:main",
            "sentinelboot=sentinelroot.boot_protect:main",
            "sentinel-update-signatures=sentinelroot.update_signatures:main",
            "sentinel-train=sentinelroot.train:main",
        ]
    },
)
