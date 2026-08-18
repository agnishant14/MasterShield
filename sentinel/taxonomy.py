"""Curated GenAI-enabled payment attack catalog used by the red-team simulator."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AttackScenario:
    id: str
    name: str
    family: str
    rail: str
    channel: str
    genai_role: str
    novelty: str
    severity: str
    description: str
    simulation_recipe: str
    leading_signals: tuple[str, ...]
    mitigations: tuple[str, ...]
    readiness: str = "simulated"

    def to_dict(self) -> dict:
        item = asdict(self)
        item["leading_signals"] = list(self.leading_signals)
        item["mitigations"] = list(self.mitigations)
        return item


ATTACKS: tuple[AttackScenario, ...] = (
    AttackScenario(
        "atk-001", "Deepfake executive payment", "authorized_push", "RTP / bank transfer",
        "Voice + messaging", "Voice cloning and an LLM sustain a convincing urgent executive conversation.",
        "High", "Critical", "An employee is induced to add a new beneficiary and authorize a high-value transfer.",
        "Generate high-value new-payee transfers after an unusual voice-led session with time pressure.",
        ("new payee", "unusual amount", "semantic urgency", "voice mismatch"),
        ("out-of-band confirmation", "beneficiary cooling period", "voice liveness"),
    ),
    AttackScenario(
        "atk-002", "Multilingual phishing takeover", "account_takeover", "Card + account",
        "Email / SMS / chat", "An LLM localizes phishing, mirrors bank tone, and adapts to victim replies.",
        "Medium", "High", "Credentials and OTPs are harvested, followed by rapid cross-channel spending.",
        "Create credential resets, new-device logins, IP risk, then card-not-present bursts.",
        ("credential reset", "new device", "IP reputation", "cross-channel velocity"),
        ("phishing-resistant authentication", "session binding", "behavioral biometrics"),
    ),
    AttackScenario(
        "atk-003", "Agentic card testing swarm", "card_testing", "Payment card",
        "E-commerce API", "Agents probe merchants, rotate payloads, and learn issuer response patterns.",
        "High", "High", "Stolen cards are validated with low-value transactions distributed across merchants.",
        "Generate many low-value attempts with device churn, merchant diversity, and short-window velocity.",
        ("10-minute velocity", "device churn", "low-value burst", "merchant diversity"),
        ("velocity graphing", "adaptive rate limits", "merchant-side bot signals"),
    ),
    AttackScenario(
        "atk-004", "Synthetic identity credit bust-out", "synthetic_identity", "Credit card",
        "Digital onboarding", "GenAI creates consistent identity documents, portraits, histories, and support interactions.",
        "Medium", "Critical", "A synthetic customer builds a clean payment history before coordinated max-out and disappearance.",
        "Simulate mature-looking accounts with weak identity provenance, rising limits, then abrupt spend escalation.",
        ("identity graph collisions", "thin-file consistency", "spend regime shift", "mule linkage"),
        ("consortium identity graph", "document forensics", "progressive exposure limits"),
    ),
    AttackScenario(
        "atk-005", "Deepfake liveness wallet provisioning", "wallet_provisioning", "Digital wallet",
        "Mobile app", "Face reenactment and injection tooling defeat weak selfie and liveness checks.",
        "High", "Critical", "A stolen card is provisioned into a fraudster-controlled wallet and used immediately.",
        "Create tokenized transactions from a zero-age device after low-confidence biometric enrollment.",
        ("biometric confidence", "new token", "device age", "post-provision velocity"),
        ("injection-resistant liveness", "device attestation", "provisioning cooling period"),
    ),
    AttackScenario(
        "atk-006", "Conversational QR substitution", "qr_diversion", "QR / instant payment",
        "Physical + chat", "Generated support messages pressure a payer to scan a substituted or remotely supplied QR.",
        "Medium", "High", "The displayed merchant identity appears plausible while funds route to a mule account.",
        "Generate first-time QR payees with semantic pressure, merchant mismatch, and elevated graph risk.",
        ("payee novelty", "merchant mismatch", "semantic pressure", "mule score"),
        ("verified merchant display", "payee risk banner", "dynamic QR signing"),
    ),
    AttackScenario(
        "atk-007", "Invoice rewrite agent", "invoice_fraud", "Bank transfer",
        "Email + document", "A mailbox agent detects invoices and rewrites beneficiary details while preserving layout.",
        "High", "Critical", "A legitimate supplier payment is silently redirected to a lookalike beneficiary.",
        "Generate normal-value business transfers with a new beneficiary and high supplier-name similarity.",
        ("beneficiary change", "supplier-name similarity", "mailbox anomaly", "first payment"),
        ("beneficiary verification", "signed invoices", "dual approval"),
    ),
    AttackScenario(
        "atk-008", "Autonomous mule orchestration", "mule_network", "RTP / bank transfer",
        "Cross-channel", "Agents recruit, instruct, rotate, and cash out mule accounts in real time.",
        "High", "Critical", "Funds fan out through coordinated accounts and converge at cash-out points.",
        "Generate high graph centrality, rapid fan-out, round amounts, and newly linked beneficiaries.",
        ("graph centrality", "fan-out", "account clusters", "cash-out timing"),
        ("real-time graph scoring", "network holds", "cross-bank intelligence"),
    ),
    AttackScenario(
        "atk-009", "Adaptive OTP relay", "otp_relay", "Card + account",
        "Voice / web", "An LLM responds to hesitation and scripts a live OTP handoff tailored to the bank flow.",
        "Medium", "High", "A victim willingly relays a one-time code that authorizes a new device or payment.",
        "Generate valid OTP authentication paired with remote-access, device, and session-behavior anomalies.",
        ("session entropy", "new device", "remote access", "typing inconsistency"),
        ("transaction-bound OTP", "number matching", "session risk step-up"),
    ),
    AttackScenario(
        "atk-010", "AI remote-access coaching", "remote_access", "Account transfer",
        "Voice + screen share", "A conversational agent patiently coaches screen sharing and bypasses warning fatigue.",
        "Medium", "Critical", "The victim operates their own trusted device while the fraudster directs each action.",
        "Generate trusted-device payments with abnormal navigation, pressure, new payee, and remote-control evidence.",
        ("remote-control process", "navigation anomaly", "new payee", "semantic pressure"),
        ("remote-access detection", "contextual warnings", "beneficiary hold"),
    ),
    AttackScenario(
        "atk-011", "GenAI support impersonation", "support_impersonation", "Account + wallet",
        "Chat / social", "A support bot mirrors brand language and maintains long, personalized scam conversations.",
        "Medium", "High", "Victims disclose credentials or approve a fraudster-controlled recovery flow.",
        "Create support-referral sessions followed by recovery, new device, and payee changes.",
        ("recovery sequence", "new device", "brand-language similarity", "payee change"),
        ("verified support channels", "recovery cooling period", "in-app confirmation"),
    ),
    AttackScenario(
        "atk-012", "AI storefront merchant bust-out", "merchant_bustout", "Card acquiring",
        "E-commerce", "GenAI mass-produces products, reviews, ads, policies, and support for a convincing fake merchant.",
        "High", "Critical", "A merchant processes a surge of sales, withdraws settlement, then fails fulfillment.",
        "Generate young merchants with synthetic content, traffic spikes, ticket growth, and settlement acceleration.",
        ("merchant age", "volume step-change", "review similarity", "refund lag"),
        ("rolling reserves", "content provenance", "settlement velocity controls"),
    ),
    AttackScenario(
        "atk-013", "Agentic refund abuse", "refund_abuse", "Card acquiring",
        "Merchant support", "Agents create persuasive evidence, vary narratives, and optimize refund success by merchant.",
        "High", "Medium", "Legitimate orders are repeatedly refunded or replaced using generated support claims.",
        "Generate high support pressure, claim similarity, refund frequency, and identity-link anomalies.",
        ("refund velocity", "claim embeddings", "delivery evidence", "identity links"),
        ("cross-merchant refund graph", "proof-of-delivery fusion", "claim friction"),
    ),
    AttackScenario(
        "atk-014", "Friendly-fraud evidence factory", "chargeback_abuse", "Payment card",
        "Dispute portal", "GenAI creates coherent dispute narratives and edited artifacts at high volume.",
        "Medium", "Medium", "Cardholders or organized actors dispute genuine transactions with fabricated evidence.",
        "Generate post-transaction disputes with repeated language patterns and inconsistent behavioral history.",
        ("dispute similarity", "device linkage", "delivery usage", "claim timing"),
        ("evidence forensics", "usage telemetry", "repeat-claim network"),
    ),
    AttackScenario(
        "atk-015", "Triangulation commerce automation", "triangulation", "Payment card",
        "Marketplace", "Agents run fake stores, place fulfillment orders with stolen cards, and automate buyer support.",
        "Medium", "High", "A buyer receives goods while the real merchant and cardholder absorb the loss.",
        "Generate mismatched buyer, payer, and delivery graphs with repeated fulfillment merchants.",
        ("address graph", "payer-recipient mismatch", "merchant concentration", "device clusters"),
        ("three-party graph models", "delivery verification", "merchant coordination"),
    ),
    AttackScenario(
        "atk-016", "Passkey fallback manipulation", "account_takeover", "Account",
        "Web / support", "A social agent manufactures device-loss context and persuades support to invoke weaker recovery.",
        "High", "High", "Strong authentication is bypassed through a convincingly narrated fallback path.",
        "Generate failed passkey attempts, support contact, recovery downgrade, and immediate high-risk action.",
        ("auth downgrade", "recovery velocity", "new device", "immediate cash-out"),
        ("recovery delay", "trusted-contact verification", "high-risk action lock"),
    ),
    AttackScenario(
        "atk-017", "Token relay device swarm", "wallet_relay", "Digital wallet",
        "Mobile / NFC", "Automation coordinates rooted devices and token relays while varying device fingerprints.",
        "High", "Critical", "Provisioned credentials are relayed across a swarm for geographically impossible purchases.",
        "Generate tokenized card-present events with device churn and impossible travel.",
        ("token-device graph", "impossible travel", "attestation", "terminal velocity"),
        ("hardware attestation", "token domain controls", "geovelocity checks"),
    ),
    AttackScenario(
        "atk-018", "Dynamic descriptor laundering", "transaction_laundering", "Card acquiring",
        "Merchant API", "Generated catalogs and descriptors rapidly reshape prohibited sales into plausible categories.",
        "High", "High", "An approved merchant covertly processes transactions for undisclosed businesses.",
        "Generate descriptor drift, MCC mismatch, correlated merchant clusters, and unusual ticket distributions.",
        ("descriptor drift", "MCC mismatch", "merchant graph", "ticket distribution"),
        ("website monitoring", "descriptor embeddings", "cluster-level underwriting"),
    ),
    AttackScenario(
        "atk-019", "AI subscription cycling", "subscription_abuse", "Payment card",
        "Digital commerce", "Agents create identities, rotate trials, consume services, and optimize chargeback timing.",
        "Medium", "Medium", "Large identity farms exploit promotions and dispute recurring charges after consumption.",
        "Generate device-linked identities, repeated trials, low initial tickets, and delayed disputes.",
        ("device identity graph", "trial velocity", "payment reuse", "consumption evidence"),
        ("entity resolution", "proof-of-use", "promotion controls"),
    ),
    AttackScenario(
        "atk-020", "Disaster donation deepfake", "social_engineering", "Card + RTP",
        "Social media", "Generated video, voice, and landing pages impersonate charities during breaking events.",
        "Medium", "High", "Emotionally urgent donations are routed to short-lived merchants or mule accounts.",
        "Generate newly created merchants/payees, viral traffic, urgent text, and fast settlement or cash-out.",
        ("merchant age", "traffic surge", "content provenance", "settlement speed"),
        ("verified charity registry", "settlement reserve", "campaign provenance"),
    ),
    AttackScenario(
        "atk-021", "Payroll diversion conversation hijack", "invoice_fraud", "Bank transfer",
        "Email / HR portal", "An LLM imitates an employee across multiple exchanges to change salary bank details.",
        "Medium", "High", "Payroll is redirected to a mule while the request appears linguistically consistent.",
        "Generate beneficiary changes shortly before payroll with new-account graph risk and text-style anomalies.",
        ("beneficiary change timing", "account age", "writing-style shift", "mule linkage"),
        ("employee self-service verification", "change cooling period", "payroll callback"),
    ),
    AttackScenario(
        "atk-022", "Synthetic supplier onboarding", "synthetic_identity", "Commercial payment",
        "Procurement portal", "GenAI creates corporate records, catalogs, references, and realistic supplier conversations.",
        "High", "Critical", "A fictitious supplier gains approval and receives payments for fabricated invoices.",
        "Generate identity-consistent but graph-sparse suppliers with rapid invoice ramp and shared infrastructure.",
        ("corporate graph depth", "shared infrastructure", "invoice ramp", "document provenance"),
        ("registry verification", "supplier graph scoring", "staged payment limits"),
    ),
    AttackScenario(
        "atk-023", "Voice-auth replay synthesis", "biometric_bypass", "Banking / call center",
        "Voice", "A generative voice model produces challenge phrases in the victim's voice on demand.",
        "High", "Critical", "Call-center authentication is passed before profile or payout details are changed.",
        "Generate borderline voice confidence with clean knowledge checks, then sensitive profile changes.",
        ("voice anti-spoof score", "channel switch", "profile change", "new payee"),
        ("challenge randomization", "anti-spoof models", "post-call confirmation"),
    ),
    AttackScenario(
        "atk-024", "Micro-merchant collusion optimizer", "merchant_collusion", "Card acquiring",
        "Merchant network", "Agents coordinate transaction timing, amounts, refunds, and devices to evade fixed rules.",
        "High", "High", "A ring of small merchants cycles cards and refunds to extract credit or launder funds.",
        "Generate coordinated merchant clusters with reciprocal cards, timed refunds, and amount shaping.",
        ("merchant-card graph", "reciprocal flows", "timed refunds", "amount shaping"),
        ("community detection", "cluster reserves", "network-level monitoring"),
    ),
)


ATTACK_BY_ID = {attack.id: attack for attack in ATTACKS}


def catalog() -> list[dict]:
    return [attack.to_dict() for attack in ATTACKS]

