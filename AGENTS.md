# Repository Guidelines

## Project Structure & Module Organization

This Java 17 Spring Boot application uses Maven. Code is under `src/main/java/com/deepaudit`; key packages are `agent`, `ai`, `recon`, `semantic` (cross-file analysis), `analysis` (deterministic hints), `codegraph`, `orchestrator`, `report`, `web`, `mapper`, and `domain`. MyBatis XML is in `src/main/resources/mappers`, portable Flyway migrations are in `src/main/resources/db/migration/common`, PostgreSQL-specific migrations are in `src/main/resources/db/migration/postgresql`, the console is in `src/main/resources/static`, and tests are in `src/test/java`.

## Build, Test, and Development Commands

- `mvn test` — run the normal JUnit suite using H2 and deterministic model doubles.
- `mvn clean verify` — rebuild from scratch, run tests, and create `target/deepaudit-java.jar`.
- `mvn spring-boot:run` — start the application with `application.yml` configuration.
- `java -jar target/deepaudit-java.jar` — run the packaged service.

`ModelApiManualIT` contains opt-in real-model checks run individually from IDEA; ordinary tests must not call paid APIs.

## Coding Style & Naming Conventions

Use four-space indentation, UTF-8, and existing Java 17 idioms. Types use `PascalCase`, members `camelCase`, and constants `UPPER_SNAKE_CASE`. Prefer focused, constructor-injected services. Use Lombok `@RequiredArgsConstructor` for straightforward final-field injection and `@Getter`/`@Setter`/`@NoArgsConstructor` for MyBatis data objects; do not use `@Data` on persisted entities or replace constructors that enforce defaults, normalize values, transform injected dependencies, or carry `@Value`/`@Qualifier`. Mapper interfaces and XML share a basename; do not introduce JPA/Hibernate. Name migrations `V<number>__short_description.sql` and never edit an applied migration.

## Testing Guidelines

Use JUnit 5, AssertJ, Spring Boot Test, MockMvc, and H2. Name automatic tests `*Test`/`*Tests`; reserve `*IT` for external checks. Cover Git source safety, commit diffing, Base/Target method matching, deletion-only hunks, signature and Guard changes, paged CodeGraph symbol discovery, on-demand impact materialization, local call-site verification, semantic resolution, evidence gates, Agent concurrency, triage decisions, large-project coverage without fixed-target truncation, project archive/restore and cleanup cascades, task cancellation, and changed APIs. Keep default tests independent of PostgreSQL, external Git hosts, CodeGraph installations, and external models; use deterministic test doubles for external integrations.

## Agent Architecture & Evidence Rules

The order is Recon → CHANGED audit-unit construction → Triage Orchestrator → professional investigation with on-demand context → Critic → Report. Projects run one at a time; professional tasks run concurrently through `professionalAgentExecutor`, configured by `deepaudit.ai.professional-agent-parallelism`.

`AuditUnitService` builds compact security-relevant units from external entries, dangerous data access/output, authorization and validation boundaries, financial operations, security configuration, deterministic hints, semantic flows, and incremental change scope. Do not send isolated getters, DTO boilerplate, constants, or unrelated methods as standalone units unless a verified call path needs them as context.

Triage decisions are strictly `INVESTIGATE` or `SKIP`. Triage compares the CHANGED Base/Target excerpts line by line and may return focus ranges and investigation questions, but it must not receive IMPACTED source or build call chains. Context uncertainty routes to `INVESTIGATE`, never to `SKIP`. Validate returned unit IDs, primary chunk IDs, dispositions, focus ranges, and vulnerability types against the current batch and the unit's candidate types.

Do not reintroduce risk scores or a fixed project-wide target count such as “top 300.” `deepaudit.ai.triage-batch-size` limits one lightweight model request only; it must not truncate total project coverage. Keep the professional executor queue capacity independent from audit selection.

Rules and semantic flows create hints, never findings, but their units are mandatory investigations so model omissions cannot silently remove them. Incremental scans must build Base/Target method snapshots, preserve method additions/modifications/deletions/signature changes and Guard additions/removals, and treat Guard removal as a mandatory investigation. Only `CHANGED` units are triage targets and may create professional tasks. Professional Agents first receive paged CodeGraph symbol candidates without source, then explicitly materialize selected Target locations as `IMPACTED`; unselected relations must not be chunked or sent to a model. CodeGraph candidates must pass local call-site verification before satisfying `verify_relation`. `CONTEXT` is materialized only by explicit architecture/security tools. A finding requires a professional hypothesis, valid chunk IDs, a `CHANGED` causal anchor, and Critic confirmation. Preserve the untrusted-code boundary and report filtering of `[SEMANTIC_FLOW]`/`[CRITIC]`.

## Security & Web Console

Do not execute repository code or add PoC execution, Docker verification, or CI/CD. Git access is read-only: never run repository hooks, submodules, LFS filters, build scripts, or checked-in executables. Incremental scans compare immutable base and target commit IDs and must retain complete project/configuration context while limiting expensive analysis to the semantic impact scope. Never expose Git tokens or development credentials in logs, reports, commits, or screenshots. Console changes must preserve SSE, polling and expanded-log state, responsive layout, and scrollbar space beside task statuses.

Archived projects must reject repository refresh and new audits. Project scan-data cleanup is allowed only after archival and after all tasks are terminal; it deletes audit-derived database rows through foreign-key cascades while preserving the project record and bare Git repository. Keep the explicit `DELETE_SCAN_DATA` confirmation gate for this destructive operation.

## Commit & Pull Request Guidelines

Use concise Conventional Commits, such as `feat(agent): parallelize investigations`. PRs should describe behavior, verification, schema/config impact, linked issues, and screenshots for console changes. Keep unrelated refactors separate.
