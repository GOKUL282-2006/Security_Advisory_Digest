from advisory_model import Advisory
from rag_engine import RAGEngine


class FakeModel:
    def encode(self, texts, convert_to_numpy=True):
        class Embeddings(list):
            def tolist(self):
                return list(self)

        return Embeddings([[1.0, 0.0] for _ in texts])


class FakeCollection:
    def __init__(self):
        self.data = {}

    def upsert(self, ids, documents, embeddings, metadatas):
        for advisory_id, metadata in zip(ids, metadatas):
            self.data[advisory_id] = metadata

    def query(self, query_embeddings, n_results, include):
        ids = list(self.data)[:n_results]
        return {"ids": [ids], "metadatas": [[self.data[item] for item in ids]], "documents": [[]]}


def test_rag_engine_store_and_search_without_external_model():
    engine = object.__new__(RAGEngine)
    engine.model = FakeModel()
    engine.collection = FakeCollection()

    engine.store_advisories(
        [Advisory("CVE-1", "nvd", "openssl", "critical", "openssl issue", ("https://example.test",))]
    )

    results = engine.semantic_search("openssl", top_k=1)

    assert results[0].id == "CVE-1"
    assert results[0].product == "openssl"
