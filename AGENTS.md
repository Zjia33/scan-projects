# Repository Guidelines

## Project Structure & Module Organization

This Java 17 Spring Boot application uses Maven. Code is under `src/main/java/com/deepaudit`; key packages are `agent`, `ai`, `recon`, `rag`, `semantic` (cross-file analysis), `analysis` (deterministic hints), `orchestrator`, `report`, `web`, `mapper`, and `domain`. MyBatis XML is in `src/main/resources/mappers`, Flyway migrations in `src/main/resources/db/migration/common`, the console in `src/main/resources/static`, and tests in `src/test/java`.

## Build, Test, and Development Commands

- `mvn test` — run the normal JUnit suite using H2 and deterministic model doubles.
- `mvn clean verify` — rebuild from scratch, run tests, and create `target/deepaudit-java.jar`.
- `mvn spring-boot:run` — start the application with `application.yml` configuration.
- `java -jar target/deepaudit-java.jar` — run the packaged service.

`ModelApiManualIT` contains opt-in real-model checks run individually from IDEA; ordinary tests must not call paid APIs.

## Coding Style & Naming Conventions

Use four-space indentation, UTF-8, and existing Java 17 idioms. Types use `PascalCase`, members `camelCase`, and constants `UPPER_SNAKE_CASE`. Prefer focused, constructor-injected services. Mapper interfaces and XML share a basename; do not introduce JPA/Hibernate. Name migrations `V<number>__short_description.sql` and never edit an applied migration.

## Testing Guidelines

Use JUnit 5, AssertJ, Spring Boot Test, MockMvc, and H2. Name automatic tests `*Test`/`*Tests`; reserve `*IT` for external checks. Cover parsing, ZIP safety, semantic resolution, evidence gates, Agent concurrency, and changed APIs. Keep default tests independent of PostgreSQL and external models.

## Agent Architecture & Evidence Rules

The order is Recon → Orchestrator → professional investigation → Critic → Report. Projects run one at a time; professional tasks run concurrently through `professionalAgentExecutor`, configured by `deepaudit.ai.professional-agent-parallelism`. Rules and semantic flows create hints, never findings. A finding requires a professional hypothesis, valid chunk IDs, and Critic confirmation. RAG results remain `RAG_CANDIDATE`s until `verify_relation` promotes them. Preserve the untrusted-code boundary and report filtering of `[SEMANTIC_FLOW]`/`[CRITIC]`.

## Security & Web Console

Do not execute uploaded code or add PoC execution, Docker verification, CI/CD, Git, or incremental scanning. Never expose development credentials in logs, reports, commits, or screenshots. Console changes must preserve SSE, polling and expanded-log state, responsive layout, and scrollbar space beside task statuses.

## Commit & Pull Request Guidelines

No Git history is available. Use concise Conventional Commits, such as `feat(agent): parallelize investigations`. PRs should describe behavior, verification, schema/config impact, linked issues, and screenshots for console changes. Keep unrelated refactors separate.
