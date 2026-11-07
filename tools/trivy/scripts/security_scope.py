"""Select source/image security scans from the complete Git diff; uncertainty scans all."""
import json
import os
from pathlib import Path
from ci_scope import changed_paths

ROOT = Path(__file__).resolve().parents[1]
IMAGES = json.loads((ROOT / "security/images.json").read_text())


def select(paths):
    all_images = [i["name"] for i in IMAGES]
    if not paths:
        return True, all_images
    source = False
    images = set()
    for path in paths:
        parts = path.split("/")
        if (not path or path.startswith("/") or "\\" in path
                or any(p in ("", ".", "..") for p in parts)
                or any(ord(c) < 32 for c in path)):
            return True, all_images
        if path.startswith((".github/", "security/")) or parts[-1] in ("AGENTS.md", "SKILL.md", ".dockerignore"):
            return True, all_images
        if path.startswith("scripts/security_") or path.startswith("scripts/test_security_"):
            return True, all_images
        if path == "docs/documentation-inventory.csv" or (path.startswith("docs/") and path.endswith(".md")) or parts[-1] == "README.md":
            continue
        source = True
        if not path.startswith(("apps/", "infra/", "scripts/")):
            return True, all_images
        matches = [i for i in IMAGES if any(path.startswith(prefix) for prefix in i["inputs"])]
        images.update(i["name"] for i in matches)
        if "Dockerfile" in parts[-1] and not matches:
            raise ValueError("New Dockerfile requires security/images.json registration")
    return source, sorted(images)


def main():
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    if event_name in ("schedule", "workflow_dispatch"):
        source, images = select([])
    else:
        try:
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
            paths = changed_paths(event_name, event, os.environ["GITHUB_SHA"])
        except Exception:
            paths = []
        source, images = select(paths)
    matrix = {"include": [i for i in IMAGES if i["name"] in images and i.get("buildable", True)]}
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
        out.write(f"source={str(source).lower()}\n")
        out.write(f"images={str(bool(images)).lower()}\n")
        out.write(f"matrix={json.dumps(matrix)}\n")
    print(json.dumps({"source": source, "images": images}))


if __name__ == "__main__":
    main()
