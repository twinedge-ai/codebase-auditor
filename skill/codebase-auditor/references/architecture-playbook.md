# Architecture Playbook

Use this reference when reviewing module graphs, service topology, circular dependencies, and boundary quality.

## Review Priorities

1. Treat generated graphs as discovery aids, not complete architecture proof.
2. Verify circular dependencies against runtime behavior before recommending refactors.
3. Prefer small boundary repairs over broad rewrites: extract an interface, move shared types, invert dependency direction, or isolate side effects.
4. Rank modules by coupling, responsibility concentration, change frequency, and blast radius.

## Circular Dependencies

- A source-level cycle can be harmless in some languages and dangerous in others.
- Escalate cycles that cross domain boundaries, initialization paths, persistence code, or service clients.
- Recommended fixes usually include moving shared constants/types to a neutral module, dependency inversion, or splitting orchestration from pure helpers.

## God Modules And Services

- A god module candidate has high fan-in, high fan-out, many routes, or unusually large line count.
- Confirm responsibility concentration before recommending extraction.
- Prefer extracting cohesive submodules with stable APIs over splitting by arbitrary file size.

## Service Topology

- Docker Compose, Kubernetes manifests, package manifests, route files, and client imports all provide partial topology evidence.
- Verify service dependencies against runtime config and deployment manifests.
- Escalate direct cross-service calls when they bypass intended gateways, authentication, observability, or retry boundaries.
