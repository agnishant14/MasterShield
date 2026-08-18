# Demo Runbook

## 90-second walkthrough

1. Open Overview. Point to F1, AUC, false-positive rate, and full attack coverage.
2. Click Attack intelligence. Search `wallet`, then filter `Critical`. Open a scenario in the Simulation Lab.
3. Run 80–120 events at Base or High intensity. Point to detected, missed, control false positives, mean risk, and the sample decisions.
4. Click Defense model. Show the confusion matrix and top feature contributions.
5. Click Retrain model. Point to the new cycle, hard cases, and the delta in F1 / FPR.
6. Finish on Judge evidence. Use the artifact checklist as the handoff to the repository and deck.

## Judge questions to pre-answer

- **Are the metrics real?** Yes, they are measured on a separate generated holdout. They are not claims about Mastercard production performance.
- **Why logistic regression?** It is a transparent baseline with stable latency and actionable feature contributions. The production boundary is intentionally modular.
- **How is fidelity assessed?** First by feature distributions and correlation checks; next by attack-family coverage and downstream detector performance; finally by replaying confirmed production cases.
- **What is the most novel part?** The attack catalog is treated as a living hypothesis graph. The detector's misses automatically become high-priority red-team cases for the next cycle.
- **How do you prevent the simulator from being dangerous?** It emits synthetic payment records and risk signals only. It does not target accounts, provide evasion instructions, or connect to payment rails.

