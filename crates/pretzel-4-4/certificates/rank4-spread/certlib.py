"""Exact interval tools of the Pretzel-(5,5) row certificate program, used here unchanged."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    'archive', ROOT.parents[2]/'pretzel-5-5/certificates/rank5-dither/certify.py')
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)
for name in ('UNIT', 'WORD', 'rat', 'mul', 'div', 'power', 'maximum', 'record'):
    globals()[name] = getattr(archive, name)
