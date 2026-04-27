# Vector / RAG Analysis

Vector and RAG analysis are optional CaseScope AI features that help analysts ask natural-language questions against indexed investigation content. They are not a replacement for the normal forensic data stores. Structured events, network logs, metadata, reports, and case state still live in PostgreSQL and ClickHouse. The vector system adds a semantic retrieval layer for content that has been imported into the RAG knowledge base.

## What RAG Means In CaseScope

RAG stands for retrieval-augmented generation. In CaseScope, the basic flow is:

1. Text content is selected for indexing.
2. CaseScope splits the content into searchable chunks.
3. Each chunk is converted into an embedding.
4. The embedding and related metadata are stored in Qdrant.
5. When an analyst asks an AI-assisted question, CaseScope embeds the question, searches Qdrant for similar chunks, and passes the retrieved context to the model.
6. The model uses the retrieved case context when generating an answer.

This helps the AI answer with case-specific information instead of relying only on the model's general training data.

## Core Components

CaseScope uses these components for vector and RAG workflows:

- **Qdrant** stores vector embeddings and searchable chunk metadata.
- **Ollama** provides the local LLM endpoint for AI-assisted responses.
- **Embedding model** converts text and questions into vectors.
- **CaseScope AI workflows** decide what content is retrieved and how it is supplied to the model.

Qdrant and Ollama are optional services. If they are not installed or configured, the rest of CaseScope can still run, but RAG-backed AI features will not be available.

## What Gets Stored In Vectors

The vector store is intended for text-like content that benefits from semantic search, such as:

- investigation notes
- case summaries
- report text
- extracted document text
- AI review context
- analyst-curated knowledge
- selected evidence text that has been prepared for AI review

The vector store is not the primary storage location for raw evidence or structured telemetry.

Examples of data that normally belong in primary stores first:

- Windows event records in ClickHouse
- Zeek network logs in ClickHouse
- user, case, file, report, job, and license metadata in PostgreSQL
- memory plugin output in PostgreSQL
- original uploaded evidence in retained storage

RAG may reference summaries or extracted text from these sources, but it should not be treated as the source of record.

## Auto Import Behavior

CaseScope's standard artifact ingestion path automatically parses and stores supported artifacts in the normal forensic stores. That does not mean every uploaded artifact is automatically added to Qdrant.

Automatic RAG import should be expected only for workflows that explicitly invoke AI/RAG indexing. When an AI-enabled workflow prepares text for semantic retrieval, CaseScope can chunk and embed that text into Qdrant so later AI questions can retrieve it.

In practical terms:

- Uploading or ingesting evidence starts the normal parser and indexing workflow.
- Parsed events and structured records go to ClickHouse or PostgreSQL.
- RAG indexing happens only when the relevant AI/RAG workflow imports content into the vector store.
- If optional AI services are disabled, unavailable, or not licensed, automatic RAG enrichment is skipped or unavailable while normal ingestion continues.

## Manual Import Behavior

Manual importing is used when an analyst or administrator wants specific text content available to RAG but it is not automatically indexed by an AI workflow.

Use manual import for content such as:

- investigation notes that should be searchable by AI
- external reports or case summaries
- selected findings or timelines
- reference material relevant to the case
- text extracted outside CaseScope

Manual import is useful when the content is important to analyst reasoning but does not naturally enter the RAG system through artifact parsing or another AI workflow.

## When RAG Is Used

RAG is used by AI-assisted analysis features when CaseScope needs case-specific context for a natural-language response.

Common use cases include:

- asking questions about indexed case material
- summarizing selected investigation context
- finding related notes, findings, or report sections by meaning instead of exact keyword
- giving the AI relevant case context before it drafts an answer
- supporting analyst follow-up questions after evidence review

RAG is not required for:

- basic login and case management
- normal artifact upload
- deterministic parsing
- ClickHouse hunting queries
- PCAP processing with Zeek
- memory processing with Volatility3
- standard IOC tracking

Those workflows should continue to work without Qdrant or Ollama unless a specific AI feature is being used.

## Why RAG Is Separate From Event Hunting

Event hunting and RAG answer different questions.

Event hunting is best for exact filtering, timelines, pivots, counts, known fields, and structured forensic review. It uses the authoritative event and telemetry data stored in ClickHouse and PostgreSQL.

RAG is best for semantic retrieval and language-based analysis over indexed text. It helps answer questions like "what activity looks related to credential abuse?" when supporting case text has already been imported into the vector store.

For investigations, use structured hunting to verify facts and use RAG to accelerate review, summarize context, and find related material.

## Configuration

Important settings include:

- `QDRANT_HOST` for the Qdrant host
- `QDRANT_PORT` for the Qdrant port
- `OLLAMA_HOST` for the Ollama endpoint
- `OLLAMA_MODEL` for the local model
- `EMBEDDING_MODEL` for embedding generation
- `EMBEDDING_DEVICE` for CPU or GPU embedding execution

The install guide recommends `EMBEDDING_DEVICE=cpu` unless the host has a validated CUDA stack.

## Operational Notes

Keep these points in mind:

- Qdrant stores derived searchable chunks, not the original evidence.
- Removing original evidence or case records does not automatically mean every derived vector has been reviewed for retention impact.
- RAG answers should be treated as analyst assistance, not ground truth.
- Important findings should be verified against source artifacts, ClickHouse records, PostgreSQL records, or retained evidence.
- Vector storage can grow over time as more case material is imported.
- AI and OpenCTI-backed features may be license-gated.

## Troubleshooting

If RAG features are unavailable:

1. Confirm Qdrant is installed and reachable on the configured host and port.
2. Confirm Ollama is running and reachable at the configured endpoint.
3. Confirm the configured model is installed in Ollama.
4. Confirm `EMBEDDING_DEVICE` is valid for the host.
5. Confirm the feature is enabled and licensed.
6. Confirm the case content has actually been imported into the vector store.

If an AI answer lacks case-specific detail, the most common cause is that the relevant content has not been indexed into Qdrant or the question did not retrieve the expected chunks.
