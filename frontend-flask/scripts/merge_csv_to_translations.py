"""Merge an English→Hindi CSV into translations/<lang>.json under 'products'.

Usage:
  python merge_csv_to_translations.py --csv ../Dataset_English_Hindi.csv --lang hi

Defaults to overwriting existing keys with CSV values.
"""
import argparse
import csv
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--csv', required=True, help='Path to CSV file (English,Hindi)')
parser.add_argument('--lang', default='hi', help='Target language code')
parser.add_argument('--translations-dir', default=str(Path(__file__).resolve().parents[1] / 'translations'))
parser.add_argument('--overwrite', action='store_true', help='Overwrite existing product mappings (default True)')
args = parser.parse_args()

csv_path = Path(args.csv)
if not csv_path.exists():
    print('CSV file not found:', csv_path)
    raise SystemExit(1)

translations_dir = Path(args.translations_dir)
translations_dir.mkdir(parents=True, exist_ok=True)
json_path = translations_dir / f'{args.lang}.json'

# Load existing translations
if json_path.exists():
    data = json.loads(json_path.read_text(encoding='utf-8'))
else:
    data = {}

products = data.get('products', {}) if isinstance(data.get('products', {}), dict) else {}

# Read CSV and build mapping; pick first Hindi occurrence per English
new_map = {}
with csv_path.open(newline='', encoding='utf-8') as f:
    reader = csv.reader(f)
    header = next(reader, None)
    for row in reader:
        if not row:
            continue
        # handle rows with more than 2 cols by taking first two
        eng = row[0].strip()
        hi = row[1].strip() if len(row) > 1 else ''
        if not eng or not hi:
            continue
        if eng not in new_map:
            new_map[eng] = hi

# Merge: default behavior is to overwrite existing products with CSV values
products.update(new_map)

# Put back and save
data['products'] = products
json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'Merged {len(new_map)} entries into {json_path} (total products: {len(products)})')
