from __future__ import annotations

from pathlib import Path
from typing import Iterable

from advisory_model import Advisory


class RAGEngine:
    def __init__(
        self,
        persist_directory: str | Path = ".chroma",
        collection_name: str = "advisories",
        model_name: str = "all-MiniLM-L6-v2",
    ) -> None:
        import chromadb
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer(model_name)
        self.client = chromadb.PersistentClient(path=str(persist_directory))
        self.collection = self.client.get_or_create_collection(collection_name)

    def create_embeddings(self, texts: list[str]) -> list[list[float]]:
        return self.model.encode(texts, convert_to_numpy=True).tolist()

    def store_advisories(self, advisories: Iterable[Advisory]) -> None:
        items = list(advisories)
        if not items:
            return
        documents = [self._document(advisory) for advisory in items]
        self.collection.upsert(
            ids=[advisory.id for advisory in items],
            documents=documents,
            embeddings=self.create_embeddings(documents),
            metadatas=[
                {
                    "source": advisory.source,
                    "product": advisory.product,
                    "severity": advisory.severity,
                    "description": advisory.description,
                    "references": "\n".join(advisory.references),
                }
                for advisory in items
            ],
        )

    def semantic_search(self, query: str, top_k: int = 5) -> list[Advisory]:
        result = self.collection.query(
            query_embeddings=self.create_embeddings([query]),
            n_results=top_k,
            include=["metadatas", "documents"],
        )
        advisories: list[Advisory] = []
        for advisory_id, metadata in zip(result.get("ids", [[]])[0], result.get("metadatas", [[]])[0]):
            advisories.append(
                Advisory(
                    id=advisory_id,
                    source=str(metadata.get("source", "")),
                    product=str(metadata.get("product", "")),
                    severity=str(metadata.get("severity", "unknown")),
                    description=str(metadata.get("description", "")),
                    references=tuple(str(metadata.get("references", "")).splitlines()),
                )
            )
        return advisories

    @staticmethod
    def _document(advisory: Advisory) -> str:
        return f"{advisory.product} {advisory.severity} {advisory.id} {advisory.description}"
