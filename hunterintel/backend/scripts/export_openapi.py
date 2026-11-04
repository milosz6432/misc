"""Write the OpenAPI schema to docs/openapi.json (run from backend/: python scripts/export_openapi.py)."""

import json
import pathlib
import sys

from hunterintel.api.app import create_app
from hunterintel.config import Settings

out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "../docs/openapi.json")
app = create_app(Settings(_env_file=None, database_url="sqlite+aiosqlite:///:memory:"))
out.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n")
print(f"wrote {out} ({len(app.openapi()['paths'])} paths)")
