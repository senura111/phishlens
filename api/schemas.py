"""Request and response models for the API (the contract in CLAUDE.md).

Pydantic checks every request against these classes before our code sees it, and
FastAPI answers 422 with the details when a request doesn't fit.

Required means present, not non-empty: a field without a default must be in the
request, but its value may be "" or []. Real emails can have no display name, no body
text (image-only emails) or no links, so empty values are normal. A *missing* field
means the extension didn't send it, which is a bug worth seeing straight away.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

# Length caps, in characters. They keep every field to a size real email needs, so
# no single field can be used to make the analysis slow. body_text has no cap of its
# own: the whole request is limited to 100 KB (api/main.py).
MAX_SENDER_EMAIL = 254  # the longest valid email address
MAX_SENDER_NAME = 256
MAX_SUBJECT = 1_000
MAX_LINK_TEXT = 2_048
MAX_LINK_HREF = 2_048
MAX_ATTACHMENT_NAME = 255  # the longest file name most file systems allow
# Count caps. Big marketing newsletters have a few hundred links, so 1,000 leaves
# room. Gmail limits attachments to 25 MB in total, so 100 is more than any real
# email has.
MAX_LINKS = 1_000
MAX_ATTACHMENTS = 100


class StrictModel(BaseModel):
    # Reject unknown fields, so a typo in the extension ("senderEmail") gives a 422
    # instead of being silently ignored.
    model_config = ConfigDict(extra="forbid")


class Link(StrictModel):
    # What the reader sees; may be "" (e.g. an image link).
    text: str = Field(max_length=MAX_LINK_TEXT)
    href: str = Field(max_length=MAX_LINK_HREF)  # where the link really goes


class AnalyzeRequest(StrictModel):
    sender_name: str = Field(max_length=MAX_SENDER_NAME)
    # Every email has a sender address, so an empty one means the extension failed
    # to read it.
    sender_email: str = Field(min_length=1, max_length=MAX_SENDER_EMAIL)
    subject: str = Field(max_length=MAX_SUBJECT)
    body_text: str
    links: list[Link] = Field(max_length=MAX_LINKS)
    # Optional: attachment file names as Gmail shows them, never their contents.
    attachments: list[Annotated[str, Field(max_length=MAX_ATTACHMENT_NAME)]] = Field(
        default=[], max_length=MAX_ATTACHMENTS
    )


class Reason(BaseModel):
    id: str
    severity: Literal["high", "medium", "low"]
    message: str


class AnalyzeResponse(BaseModel):
    verdict: Literal["phishing", "suspicious", "safe"]
    score: float = Field(ge=0.0, le=1.0)
    reasons: list[Reason]


class HealthResponse(BaseModel):
    status: Literal["ok"]
