# ADR 0006: MITRE Mapping and Scoring Methodology

## Context
For Phase 6, the SOAR platform needs to automatically map incoming threat alerts to the MITRE ATT&CK framework (Tactics and Techniques) and use this classification to compute or adjust a dynamic, explainable severity score for the case. We need a model that is both explainable to security analysts (avoiding black-box logic) and capable of handling overlapping threat behaviors.

## Proposed Design Decisions

### 1. Hybrid Mapping Strategy (Static Rules + LLM Fallback)
We will implement a hybrid classification strategy to map alerts to MITRE ATT&CK techniques:
- **Deterministic Heuristic Rules (Primary)**: We will maintain a predefined rule-set matching alert attributes (e.g., signature name, title, description keywords, source type) directly to MITRE Technique IDs (e.g., matching "brute force" to `T1110`). This provides 100% deterministic and explainable mapping.
- **LLM-Assisted Classification (Secondary/Fallback)**: If no static rule matches, or for complex unstructured alerts, we will utilize the Gemini API to analyze the description and raw payload, recommending matching Techniques with a confidence threshold.

### 2. Multi-Technique Support (One-to-Many Alert Mapping)
A single alert can map to multiple MITRE Techniques and Tactics, as real-world security events often span across stages (e.g., an alert containing a credential dump and command-and-control behavior). We will support linking an Alert to multiple MITRE Technique associations.

### 3. Tactic-Weighted Severity Scoring
The severity score for a Case will be dynamically adjusted based on the mapped MITRE Tactics, prioritizing threat lifecycle stages:
- **Tactic Weighting**: Pre-compromise or early tactics (e.g., *Reconnaissance*, *Resource Development*) add low score weights (+1). Late-stage compromise tactics (e.g., *Lateral Movement*, *Credential Access*, *Collection*) add medium weights (+2). Post-compromise action tactics (e.g., *Exfiltration*, *Impact*) add critical weights (+4).
- **Dynamic Score Formula**:
  $$\text{Case Score} = \text{Base Severity} + \max(\text{Tactic Weights}) + \text{IOC Score Adjustments}$$
  This ensures that early stage activities don't artificially inflate severity, while any high-impact actions (like Exfiltration) immediately escalate the Case to a Critical rating.

## Consequences
- **Positive**: High explainability. Security analysts can inspect exactly *why* a case has a certain score, citing specific mapped techniques and the tactic weights.
- **Neutral**: Requires keeping a local lookup table of MITRE Technique/Tactic metadata, which we will store in a lookup schema.
