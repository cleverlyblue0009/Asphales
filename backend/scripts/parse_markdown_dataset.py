#!/usr/bin/env python3
"""
Parse the markdown training dataset and convert to CSV format.
Extracts safe and threat messages from all 15 languages.
"""

import json
import csv
import re
from pathlib import Path
from typing import List, Dict, Tuple


def extract_json_from_markdown(md_file_path: str) -> List[Dict]:
    """
    Extract JSON objects from markdown file.
    Each language section contains a JSON object with safe/threat data.
    """
    with open(md_file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    json_blocks = []

    # Split content by language headers (handles various formats: "HINDI:", "TAMIL-ENGLISH:", "HINDI ENGLISH:", "MARATHI \- ENGLISH:")
    language_sections = re.split(r'\n([A-Z][A-Z\s\-\\]+):\s*\n', content)

    # Process each language section
    for i in range(1, len(language_sections), 2):
        if i + 1 >= len(language_sections):
            break

        language_header = language_sections[i]
        section_content = language_sections[i + 1]

        # Find JSON block in this section
        # Look for opening brace to closing brace
        match = re.search(r'\{[\s\S]*?\}\s*\}', section_content)

        if not match:
            print(f"Warning: No JSON found for {language_header}")
            continue

        json_str = match.group(0)

        try:
            # Clean up the JSON string (remove markdown escaping)
            json_str = json_str.replace('\\[', '[').replace('\\]', ']')
            json_str = json_str.replace('\\!', '!').replace('\\{', '{').replace('\\}', '}')
            json_str = json_str.replace('\\,', ',').replace('\\.', '.')
            json_str = json_str.replace('\\:', ':').replace('\\;', ';')

            # Parse JSON
            data = json.loads(json_str)
            json_blocks.append(data)
            print(f"✓ Parsed {language_header}: {list(data.keys())}")

        except json.JSONDecodeError as e:
            # Try to extract language name from header and create manual structure
            print(f"⚠ JSON parse failed for {language_header}, trying manual extraction: {e}")

            # Try to extract safe and threat arrays manually
            safe_match = re.search(r'"safe"\s*:\s*\[(.*?)\]\s*,', section_content, re.DOTALL)
            threat_match = re.search(r'"threat"\s*:\s*\[(.*?)\]', section_content, re.DOTALL)

            if safe_match or threat_match:
                language_name = language_header.title().replace('-', ' ')
                manual_data = {language_name: {"safe": [], "threat": []}}

                if safe_match:
                    safe_content = safe_match.group(1)
                    # Extract quoted strings
                    safe_items = re.findall(r'"([^"]+)"', safe_content)
                    manual_data[language_name]["safe"] = [s.replace('\\!', '!') for s in safe_items]

                if threat_match:
                    threat_content = threat_match.group(1)
                    # Extract threat objects
                    threat_objects = re.finditer(r'\{\s*"text"\s*:\s*"([^"]+)"\s*,\s*"link"\s*:\s*"([^"]+)"\s*\}', threat_content)
                    manual_data[language_name]["threat"] = [
                        {"text": t.group(1).replace('\\!', '!'), "link": t.group(2)}
                        for t in threat_objects
                    ]

                if manual_data[language_name]["safe"] or manual_data[language_name]["threat"]:
                    json_blocks.append(manual_data)
                    print(f"✓ Manually extracted {language_name}: {len(manual_data[language_name]['safe'])} safe, {len(manual_data[language_name]['threat'])} threat")

    return json_blocks


def convert_to_training_data(json_blocks: List[Dict]) -> List[Tuple[str, int, str]]:
    """
    Convert JSON blocks to training data format.
    Returns list of (text, label, language) tuples.
    label: 0 = safe, 1 = threat/phishing
    """
    training_data = []

    for block in json_blocks:
        # Each block has one key which is the language name
        for language_name, data in block.items():
            # Extract safe messages
            if 'safe' in data:
                for msg in data['safe']:
                    training_data.append((msg, 0, language_name))

            # Extract threat messages
            if 'threat' in data:
                for item in data['threat']:
                    # Threat items can be strings or dicts with 'text' and 'link'
                    if isinstance(item, dict):
                        text = item.get('text', '')
                        # Optionally include link in the text for more context
                        # text_with_link = f"{text} {item.get('link', '')}"
                        training_data.append((text, 1, language_name))
                    elif isinstance(item, str):
                        training_data.append((item, 1, language_name))

    return training_data


def save_to_csv(training_data: List[Tuple[str, int, str]], output_path: str):
    """Save training data to CSV file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        # Write header
        writer.writerow(['text', 'label', 'language'])

        # Write data
        for text, label, language in training_data:
            writer.writerow([text, label, language])

    print(f"Saved {len(training_data)} examples to {output_path}")


def main():
    """Main function to parse markdown and create CSV dataset."""
    # Paths
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent

    md_file = project_root / "Dataset of training (Threats and safe messages) (15 languages).md"
    output_csv = script_dir.parent / "data" / "phishing_multilingual_from_md.csv"

    print(f"Reading markdown file: {md_file}")

    # Extract JSON blocks
    json_blocks = extract_json_from_markdown(str(md_file))
    print(f"Extracted {len(json_blocks)} language blocks")

    # Convert to training data
    training_data = convert_to_training_data(json_blocks)
    print(f"Converted to {len(training_data)} training examples")

    # Count by language and label
    language_counts = {}
    label_counts = {0: 0, 1: 0}

    for text, label, language in training_data:
        language_counts[language] = language_counts.get(language, 0) + 1
        label_counts[label] += 1

    print("\nDataset statistics:")
    print(f"Total examples: {len(training_data)}")
    print(f"Safe messages: {label_counts[0]}")
    print(f"Threat messages: {label_counts[1]}")
    print(f"\nLanguages found: {len(language_counts)}")
    for lang, count in sorted(language_counts.items()):
        print(f"  {lang}: {count} examples")

    # Save to CSV
    save_to_csv(training_data, str(output_csv))
    print(f"\n✓ Dataset created successfully!")
    print(f"Output: {output_csv}")


if __name__ == "__main__":
    main()
