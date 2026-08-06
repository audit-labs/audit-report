"""Control catalog.

A small, plain-language reference for every control code a ruleset may cite.
Control codes are written as ``FRAMEWORK:CODE`` (for example ``SOC2:CC6.1``).
The catalog is deliberately not exhaustive — it covers the codes the bundled
rulesets actually reference. Adding a framework means adding its codes here and
citing them from a ruleset.

Like gh-attest, this tool produces *evidence*, not a compliance verdict: a
mapping says a signal is relevant to a control, not that the control is met.
"""

# framework code -> human-readable name
FRAMEWORKS = {
    "SOC2": "SOC 2 (Trust Services Criteria)",
    "ISO": "ISO/IEC 27001:2022 Annex A",
    "NIST": "NIST SP 800-53 Rev. 5",
}

# "FRAMEWORK:CODE" -> one-line description of the control
CONTROLS = {
    # SOC 2 Trust Services Criteria
    "SOC2:CC6.1": "Logical access security — restrict access to protected information assets.",
    "SOC2:CC6.2": "Register and authorize new users before granting access.",
    "SOC2:CC6.3": "Manage access rights based on roles and least privilege.",
    "SOC2:CC6.6": "Restrict access from outside the system boundary.",
    "SOC2:CC6.7": "Restrict the transmission and movement of information.",
    "SOC2:CC7.1": "Detect and monitor for new vulnerabilities and misconfigurations.",
    "SOC2:CC7.2": "Monitor system components for anomalies and security events.",
    "SOC2:CC8.1": "Authorize, design, and track changes to infrastructure and software.",
    # ISO/IEC 27001:2022 Annex A
    "ISO:A.5.15": "Access control — rules based on business and security requirements.",
    "ISO:A.5.17": "Authentication information — management of secrets and MFA.",
    "ISO:A.5.18": "Access rights — provisioning, review, and removal.",
    "ISO:A.8.2": "Privileged access rights — restricted and managed.",
    "ISO:A.8.9": "Configuration management — secure baseline configuration.",
    "ISO:A.8.15": "Logging — record events for monitoring and investigation.",
    "ISO:A.8.20": "Network security — securing networks and network services.",
    "ISO:A.8.32": "Change management — control changes to information systems.",
    # NIST SP 800-53 Rev. 5
    "NIST:AC-2": "Account management — establish, review, and disable accounts.",
    "NIST:AC-6": "Least privilege — authorize the minimum access necessary.",
    "NIST:AU-2": "Event logging — determine and record auditable events.",
    "NIST:CM-6": "Configuration settings — establish and enforce secure settings.",
    "NIST:IA-2": "Identification and authentication — multifactor for accounts.",
    "NIST:IA-5": "Authenticator management — password strength and lifecycle.",
    "NIST:SC-7": "Boundary protection — control communications at boundaries.",
}


def describe(control: str) -> str:
    """Return the description for a control code, or a placeholder if unknown."""
    return CONTROLS.get(control, "(no description on file)")


def framework_of(control: str) -> str:
    """Return the framework short code for a control code (text before ':')."""
    return control.split(":", 1)[0]
