import pathlib
import sys

# Make `import aah` work without an editable install (src-layout).
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))
