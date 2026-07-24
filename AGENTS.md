# Repository Guidelines

## Project Structure & Module Organization

This Java 17 Spring Boot application uses Maven. Code is under `src/main/java/com/deepaudit`; key packages are `agent`, `ai`, `recon`, `rag`, `semantic` (cross-file analysis), `analysis` (deterministic hints), `orchestrator`, `report`, `web`, `mapper`, and `domain`. MyBatis XML is in `src/main/resources/mappers`, portable Flyway migrations are in `src/main/resources/db/migration/common`, PostgreSQL/pgvector migrations are in `src/main/resources/db/migration/postgresql`, the console is in `src/main/resources/static`, and tests are in `src/test/java`.

## Build, Test, and Development Commands

- `mvn test` — run the normal JUnit suite using H2 and deterministic model doubles.
- `mvn clean verify` — rebuild from scratch, run tests, and create `target/deepaudit-java.jar`.
- `mvn spring-boot:run` — start the application with `application.yml` configuration.
- `java -jar target/deepaudit-java.jar` — run the packaged service.

`ModelApiManualIT` contains opt-in real-model checks run individually from IDEA; ordinary tests must not call paid APIs.

## Coding Style & Naming Conventions

Use four-space indentation, UTF-8, and existing Java 17 idioms. Types use `PascalCase`, members `camelCase`, and constants `UPPER_SNAKE_CASE`. Prefer focused, constructor-injected services. Use Lombok `@RequiredArgsConstructor` for straightforward final-field injection and `@Getter`/`@Setter`/`@NoArgsConstructor` for MyBatis data objects; do not use `@Data` on persisted entities or replace constructors that enforce defaults, normalize values, transform injected dependencies, or carry `@Value`/`@Qualifier`. Mapper interfaces and XML share a basename; do not introduce JPA/Hibernate. Name migrations `V<number>__short_description.sql` and never edit an applied migration.

## Testing Guidelines

Use JUnit 5, AssertJ, Spring Boot Test, MockMvc, and H2. Name automatic tests `*Test`/`*Tests`; reserve `*IT` for external checks. Cover Git source safety, commit diffing, semantic resolution, vector recall boundaries, evidence gates, Agent concurrency, and changed APIs. Keep default tests independent of PostgreSQL, external Git hosts, and external models; use the memory vector-recall implementation only in the test profile.

## Agent Architecture & Evidence Rules

The order is Recon → Orchestrator → professional investigation → Critic → Report. Projects run one at a time; professional tasks run concurrently through `professionalAgentExecutor`, configured by `deepaudit.ai.professional-agent-parallelism`. Rules and semantic flows create hints, never findings. A finding requires a professional hypothesis, valid chunk IDs, and Critic confirmation. RAG results remain `RAG_CANDIDATE`s until `verify_relation` promotes them. Preserve the untrusted-code boundary and report filtering of `[SEMANTIC_FLOW]`/`[CRITIC]`.

## Security & Web Console

Do not execute repository code or add PoC execution, Docker verification, or CI/CD. Git access is read-only: never run repository hooks, submodules, LFS filters, build scripts, or checked-in executables. Full scans analyze one immutable commit snapshot; incremental scans compare immutable base and target commit IDs and must retain complete project/configuration context while limiting expensive analysis to the semantic impact scope. Never expose Git tokens or development credentials in logs, reports, commits, or screenshots. Console changes must preserve SSE, polling and expanded-log state, responsive layout, and scrollbar space beside task statuses.

## Commit & Pull Request Guidelines

Use concise Conventional Commits, such as `feat(agent): parallelize investigations`. PRs should describe behavior, verification, schema/config impact, linked issues, and screenshots for console changes. Keep unrelated refactors separate.
