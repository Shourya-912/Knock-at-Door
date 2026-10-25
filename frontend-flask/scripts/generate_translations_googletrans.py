"""Generate product translations from MongoDB vendor items using googletrans.

Usage:
  python generate_translations_googletrans.py --targets hi

This script:
- Connects to the MongoDB used by the app (reads URI from a constant in this file; edit if needed)
- Collects distinct product/item names from vendors.items.name
- Uses googletrans to translate them to the target language(s)
- Merges results into translations/<lang>.json under the "products" key
"""

import argparse
import json
from pathlib import Path
from googletrans import Translator
from pymongo import MongoClient

# Update this if your app uses a different URI or prefer to supply via env var
MONGO_URI = "mongodb+srv://shourchourasia912:Knock912@cluster0.k07ix.mongodb.net/knockatdoor?retryWrites=true&w=majority"
DB_NAME = 'knockatdoor'
VENDORS_COLL = 'vendors'
TRANSLATIONS_DIR = Path(__file__).resolve().parents[1] / 'translations'


def collect_product_names(client):
    db = client[DB_NAME]
    coll = db[VENDORS_COLL]
    names = set()
    for v in coll.find({}, { 'items.name': 1 }):
        items = v.get('items') or []
        for it in items:
            name = (it.get('name') or '').strip()
            if name:
                names.add(name)
    return sorted(names)


def load_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return {}


def save_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


def main(targets):
    client = MongoClient(MONGO_URI)
    names = collect_product_names(client)
    if not names:
        print('No product names found in DB.')
        return

    translator = Translator()

    for lang in targets:
        print(f'Translating {len(names)} product names to: {lang}')
        # translate supports list input
        translations = translator.translate(names, dest=lang)
        mapping = {}
        for src, tr in zip(names, translations):
            mapping[src] = tr.text

        # merge into translations file
        tpath = TRANSLATIONS_DIR / f'{lang}.json'
        data = load_json(tpath)
        data_products = data.get('products', {})
        data_products.update(mapping)
        data['products'] = data_products
        save_json(tpath, data)
        print(f'Updated {tpath} with {len(mapping)} product translations')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--targets', nargs='+', required=True, help='Target language codes like hi fr')
    args = parser.parse_args()
    main(args.targets)
