# Security Policy

Network Broker is an early-stage security-oriented prototype. It has not yet undergone an independent security assessment and should not be used to protect or access production network infrastructure.

## Supported versions

Until the project publishes versioned releases, security fixes are made only on the latest commit of the `main` branch.

| Version | Supported |
| --- | --- |
| Latest `main` | Yes |
| Older commits and forks | No |

## Reporting a vulnerability

Please do not report suspected vulnerabilities in a public GitHub issue, discussion, pull request, or other public channel.

Use GitHub's private vulnerability reporting for this repository:

<https://github.com/gwoodwa1/network-broker/security/advisories/new>

Include, where possible:

- The affected component and revision.
- The security impact and realistic attack scenario.
- Reproduction instructions or a minimal proof of concept.
- Any prerequisites, configuration, or environment details.
- Suggested mitigations or fixes, if known.

Do not include real credentials, customer data, captured network evidence, private keys, or details of systems you are not authorised to test.

## Response process

The project aims to:

- Acknowledge a complete report within seven days.
- Confirm the initial severity and next steps within 14 days.
- Coordinate remediation and disclosure with the reporter.
- Credit reporters who request attribution, unless legal or privacy constraints prevent it.

These are response targets rather than contractual service levels. Fix timing depends on severity, complexity, maintainer availability, and the maturity of the project.

## Scope

Examples of relevant reports include:

- Authentication, tenant-isolation, or authorization bypasses.
- Fencing, grant, credential, or evidence-signature weaknesses.
- Cross-actor or cross-tenant evidence disclosure.
- Command, selector, parser, or transport injection.
- Credential, private-key, captured-evidence, or audit-data exposure.
- Denial-of-service paths that bypass documented resource bounds.
- Vulnerable dependencies that are reachable from this code.

General feature requests, hardening suggestions without a concrete vulnerability, and bugs without security impact can use the public issue tracker.

## Safe harbour

Good-faith research should remain limited to systems and data you own or are explicitly authorised to test. Avoid privacy violations, service disruption, destructive actions, persistence, social engineering, and access beyond what is necessary to demonstrate the issue.

The maintainers will make a good-faith effort not to pursue action against research that follows this policy, promptly reports findings, avoids harm, and allows reasonable time for remediation before disclosure. This statement does not authorise testing of third-party systems or override applicable law.
