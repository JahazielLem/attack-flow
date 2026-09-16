import { describe, expect, it } from "vitest";
import { parseSourceObjectsFromManifest } from "./download_stix_source.mjs";

function mitreReference(externalId) {
    return {
        source_name: "mitre-attack",
        external_id: externalId,
        url: `https://attack.mitre.org/${externalId}`
    };
}

describe("download_stix_source", () => {
    it("parses defensive objects and stores their outgoing STIX relationships", () => {
        const data = {
            objects: [
                {
                    type: "x-mitre-tactic",
                    id: "x-mitre-tactic--initial-access",
                    name: "Initial Access",
                    x_mitre_shortname: "initial-access",
                    external_references: [mitreReference("TA0001")]
                },
                {
                    type: "attack-pattern",
                    id: "attack-pattern--phishing",
                    name: "Phishing",
                    description: "A technique.",
                    kill_chain_phases: [
                        {
                            kill_chain_name: "mitre-attack",
                            phase_name: "initial-access"
                        }
                    ],
                    external_references: [mitreReference("T1566")]
                },
                {
                    type: "course-of-action",
                    id: "course-of-action--training",
                    name: "User Training",
                    description: "A mitigation.",
                    external_references: [mitreReference("M1017")]
                },
                {
                    type: "x-mitre-detection-strategy",
                    id: "x-mitre-detection-strategy--phishing-detection",
                    name: "Detect Phishing",
                    description: "A detection strategy.",
                    external_references: [mitreReference("DET0001")]
                },
                {
                    type: "relationship",
                    id: "relationship--training-mitigates-phishing",
                    relationship_type: "mitigates",
                    source_ref: "course-of-action--training",
                    target_ref: "attack-pattern--phishing"
                },
                {
                    type: "relationship",
                    id: "relationship--detection-detects-phishing",
                    relationship_type: "detects",
                    source_ref: "x-mitre-detection-strategy--phishing-detection",
                    target_ref: "attack-pattern--phishing"
                }
            ]
        };

        const objects = parseSourceObjectsFromManifest(data);
        const technique = objects.find(obj => obj.id === "T1566");
        const tactic = objects.find(obj => obj.id === "TA0001");
        const mitigation = objects.find(obj => obj.id === "M1017");
        const detection = objects.find(obj => obj.id === "DET0001");

        expect(technique?.tactics?.map(obj => obj.id)).toEqual(["TA0001"]);
        expect(tactic?.techniques?.map(obj => obj.id)).toEqual(["T1566"]);
        expect(mitigation?.stixRelationships).toContainEqual({
            relationshipType: "mitigates",
            targetRef: "attack-pattern--phishing"
        });
        expect(detection?.stixRelationships).toContainEqual({
            relationshipType: "detects",
            targetRef: "attack-pattern--phishing"
        });
    });

    // Analytics link to detections via external_reference URL, not STIX relationships.
    it("aggregates analytic log sources onto detection strategies", () => {
        const data = {
            objects: [
                {
                    type: "x-mitre-detection-strategy",
                    id: "x-mitre-detection-strategy--phishing-detection",
                    name: "Detect Phishing",
                    description: "A detection strategy.",
                    external_references: [mitreReference("DET0001")]
                },
                {
                    type: "x-mitre-analytic",
                    id: "x-mitre-analytic--phishing-windows",
                    name: "Phishing on Windows",
                    external_references: [{
                        source_name: "mitre-attack",
                        external_id: "AN0001",
                        url: "https://attack.mitre.org/detectionstrategies/DET0001#AN0001"
                    }],
                    x_mitre_log_source_references: [
                        {
                            name: "WinEventLog:Security",
                            channel: "EventCode=4688"
                        }
                    ]
                },
                {
                    type: "x-mitre-analytic",
                    id: "x-mitre-analytic--phishing-linux",
                    name: "Phishing on Linux",
                    external_references: [{
                        source_name: "mitre-attack",
                        external_id: "AN0002",
                        url: "https://attack.mitre.org/detectionstrategies/DET0001#AN0002"
                    }],
                    x_mitre_log_source_references: [
                        {
                            name: "auditd:SYSCALL",
                            channel: "execve"
                        },
                        {
                            name: "WinEventLog:Security",
                            channel: "EventCode=4688"
                        }
                    ]
                }
            ]
        };

        const detection = parseSourceObjectsFromManifest(data).find(obj => obj.id === "DET0001");

        expect(detection?.log_sources).toEqual([
            { name: "WinEventLog:Security", channel: "EventCode=4688" },
            { name: "auditd:SYSCALL", channel: "execve" }
        ]);
        expect(detection?.analytics).toBeUndefined();
    });
});
