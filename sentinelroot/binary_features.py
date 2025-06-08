import lief
from typing import Dict

class BinaryFeatureExtractor:
    """Extract simple static features from ELF binaries."""

    def extract(self, path: str) -> Dict[str, float]:
        try:
            binary = lief.parse(path)
        except Exception:
            return {}
        features = {
            'size': float(binary.virtual_size or 0),
            'symbols': float(len(binary.symbols)),
            'imports': float(len(binary.imported_functions)),
            'sections': float(len(binary.sections)),
            'has_debug': float(any(s.name == '.debug_info' for s in binary.sections)),
        }
        return features
