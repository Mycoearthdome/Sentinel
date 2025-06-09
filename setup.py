from setuptools import setup, find_packages

setup(
    name="sentinelroot",
    version="0.1.0",
    description="SentinelRoot heuristic monitoring tools",
    packages=find_packages(),
    include_package_data=True,
    package_data={"sentinelroot": ["malicious_ips.json"]},
)
