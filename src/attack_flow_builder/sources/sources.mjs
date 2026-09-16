/** Official sources; collection versions are read from the downloaded STIX bundles. */
const ATTACK_BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master";

export const STIX_SOURCES = {
    MitreAttack: {
        urls: ["enterprise", "ics", "mobile"].map(domain => `${ATTACK_BASE_URL}/${domain}-attack/${domain}-attack.json`),
        documentationUrl: "https://attack.mitre.org/resources/"
    },
    MitreAtlas: {
        urls: ["https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/refs/heads/main/dist/stix-atlas.json"],
        documentationUrl: "https://atlas.mitre.org/"
    },
    MitreF3: {
        urls: ["https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/refs/heads/main/public/f3-stix.json"],
        documentationUrl: "https://ctid.mitre.org/projects/fight-financial-fraud/"
    },
    MitreSparta: {
        urls: ["https://sparta.aerospace.org/download/STIX?f=latest"],
        documentationUrl: "https://sparta.aerospace.org/resources/user-guide"
    },
    SpaceShield: {
        urls: ["https://spaceshield.esa.int/stix/space-attack.json"],
        documentationUrl: "https://spaceshield.esa.int/"
    }
};

export const MITRE_DEFEND_URL = "https://d3fend.mitre.org/api/matrix-graph.json";
