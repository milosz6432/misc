"""Local-only tools."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from hunterintel.api.deps import Container, get_container, inbound_limit, require_auth
from hunterintel.services.filetype import FileTooLargeError, hash_stream

router = APIRouter(
    prefix="/api/v1/tools",
    tags=["tools"],
    dependencies=[Depends(require_auth), Depends(inbound_limit)],
)


@router.post(
    "/file-hash",
    summary="Hash a local file and identify its type — the file is never stored or forwarded",
    description=(
        "Send the raw file as the request body (`Content-Type: application/octet-stream`), e.g. "
        "`curl --data-binary @sample.bin -H 'X-Filename: sample.bin' …`. Raw bodies are used instead of "
        "multipart so the server never spools an upload to disk. The bytes are streamed through "
        "MD5/SHA-1/SHA-256 and discarded. To look the hash up, submit it to `/enrich` explicitly."
    ),
)
async def file_hash(request: Request, c: Container = Depends(get_container)) -> dict[str, Any]:
    limit = c.settings.max_upload_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, {"code": "too_large", "message": f"limit is {limit} bytes"})
    try:
        result = await hash_stream(request.stream(), limit)
    except FileTooLargeError as exc:
        raise HTTPException(413, {"code": "too_large", "message": str(exc)}) from exc
    if result["size"] == 0:
        raise HTTPException(
            422, {"code": "empty_body", "message": "send the file bytes as the request body"}
        )
    name = re.sub(r"[^\w.\- ]", "_", request.headers.get("x-filename", ""))[:128]
    return {"filename": name or None, **result}
