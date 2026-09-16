# Scan the STIX directory json files to generate TypeScript definitions for each
# Open Vocabulary identifier's predefined values.

import json
import re
from pathlib import Path

def get_dir_files(dir):
    p = Path(dir)
    files = [str(file.resolve()) for file in p.rglob("*") if file.is_file()]
    return files

def kebab_to_pascal(kebab_str: str) -> str:
    s = re.sub(r"(-)+", " ", kebab_str).title().replace(" ", "")
    return s

def get_value_str(definition: dict) -> str:
    result = "[\n"
    options = definition["enum"]
    for o in options:
        result += f"\t[\"{o}\", \"{o}\"],\n"
    result += "];"
    return result

if __name__ == "__main__":
    stix_files = get_dir_files('oasis-open')

    ts_contents = ""

    ov_set = set()

    for file_path in stix_files:
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
                if 'definitions' not in data:
                    continue
                for key in data["definitions"]:
                    # Assume ov identifiers are unique throughout stix.
                    if key in ov_set:
                        continue
                    ov_set.add(key)
                    if key.endswith("-ov"):
                        val = get_value_str(data['definitions'][key])

                        ts_contents += f"export const {kebab_to_pascal(key)} : [string, string][] = {val}\n"

        except FileNotFoundError:
            print('File not found')
        except json.JSONDecodeError:
            print('json decode error')
    print(ts_contents)
