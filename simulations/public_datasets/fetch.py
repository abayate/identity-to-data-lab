"""Downloads the raw public datasets listed in sources.yml into data/raw/splunk_attack_data/.

Run from the repo root (needs internet; you only need to do this once, because the
raw files are committed):

    python -m simulations.public_datasets.fetch

For each dataset it saves the log file and the dataset's metadata (.yml) under the
dataset's name, plus the upstream LICENSE. The repository stores its logs with Git
LFS, which is why `base_url` points at media.githubusercontent.com: that host
serves the real file instead of the small LFS pointer stub.
"""

import sys
import urllib.request
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SOURCES_PATH = Path(__file__).resolve().parent / "sources.yml"
RAW_DIR = REPO_ROOT / "data" / "raw" / "splunk_attack_data"


def load_sources(path=SOURCES_PATH):
    """Read sources.yml and return it as a dict."""
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def raw_log_path(dataset, raw_dir=RAW_DIR):
    """Where a dataset's raw log file is stored locally, e.g. .../device_code_phishing.log"""
    return Path(raw_dir) / f"{dataset['name']}.log"


def download(url, destination):
    """Download one URL to a file and refuse to save a Git LFS pointer stub by mistake."""
    with urllib.request.urlopen(url, timeout=60) as response:
        content = response.read()
    if content.startswith(b"version https://git-lfs.github.com/spec/"):
        raise RuntimeError(f"{url} returned a Git LFS pointer, not the file")
    destination.write_bytes(content)
    print(f"  saved {destination.name} ({len(content):,} bytes)")


def main():
    sources = load_sources()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    download(sources["license_url"], RAW_DIR / "LICENSE")
    for dataset in sources["datasets"]:
        print(f"{dataset['name']}:")
        download(f"{sources['base_url']}/{dataset['path']}", raw_log_path(dataset))
        download(f"{sources['metadata_base_url']}/{dataset['metadata']}",
                 RAW_DIR / f"{dataset['name']}.metadata.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
