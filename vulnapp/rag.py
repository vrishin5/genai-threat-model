from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

DOCS_DIR = Path(__file__).resolve().parent / "docs"


@dataclass
class Document:
    name: str
    text: str


def _load_documents() -> list[Document]:
    return [
        Document(name=path.name, text=path.read_text())
        for path in sorted(DOCS_DIR.glob("*.md"))
    ]


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


class KnowledgeBase:
    """Deliberately simple keyword-overlap retrieval — no embeddings, no
    dependencies. This is a vulnerability demo, not a RAG reference
    implementation: the point is that whatever comes back is dropped into
    the model's context unsanitized and untrusted (see agent.py), which is
    exactly the indirect-injection vector the harness targets.
    """

    def __init__(self) -> None:
        self._docs = _load_documents()

    def search(self, query: str, top_k: int = 2) -> list[Document]:
        query_tokens = _tokenize(query)
        if not query_tokens:
            return []

        scored = []
        for doc in self._docs:
            overlap = len(query_tokens & _tokenize(doc.text))
            if overlap > 0:
                scored.append((overlap, doc))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [doc for _, doc in scored[:top_k]]
