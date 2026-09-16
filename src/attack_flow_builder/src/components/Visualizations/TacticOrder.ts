/** Master order of tactic names. */
const tactics: string[] = [
    "Reconnaissance", // ENT, MOB, ICS, ATL, F3
    "Resource Development", // ENT, MOB, ICS, ATL, F3
    "Initial Access", // ENT, MOB, ICS, ATL, F3
    "AI Model Access", // ATL
    "Execution", // ENT, MOB, ICS, ATL, F3
    "Persistence", // ENT, MOB, ICS, ATL
    "Privilege Escalation", // ENT, MOB, ICS, ATL
    "Stealth", // ENT, MOB, ICS, F3
    "Defense Impairment", // ENT, MOB, ICS, F3
    "Defense Evasion", // ATL
    "Positioning", // F3
    "Credential Access", // ENT, MOB, ICS, ATL
    "Discovery", // ENT, MOB, ICS, ATL
    "Lateral Movement", // ENT, MOB, ICS, ATL
    "Collection", // ENT, MOB, ICS, ATL
    "AI Attack Staging", // ATL
    "Command and Control", // ENT, MOB, ICS, ATL
    "Exfiltration", // ENT, MOB, ICS, ATL
    "Impact", // ENT, MOB, ICS, ATL
    "Monetization", // F3
    "Model", // D3
    "Harden", // D3
    "Detect", // D3
    "Isolate", // D3
    "Deceive", // D3
    "Evict", // D3
    "Restore" // D3
];

const tacticsToOrders = new Map<string, number>();
tactics.forEach((tactic, index) => tacticsToOrders.set(tactic, index));

/**
 * Get the approximate position of where a tactic appears in the attack chain
 * according to a master list of tactics. If the tactic is not known, the end
 * position of the master list is returned.
 * @param tacticName name of tactic
 * @returns The integer position a tactic appears at in the master list.
 */
export function getTacticOrder(tacticName: string) : number {
    return tacticsToOrders.get(tacticName) ?? tactics.length;
}
