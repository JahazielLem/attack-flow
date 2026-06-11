import { fetchJson } from "./source_utils.mjs";

/**
 * The base URLs for source repositories.
 */
const ATTACK_BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master";

/**
 * The GitHub API endpoint for the versioned SPARTA data directory.
 */
const SPARTA_DIR_URL = "https://api.github.com/repos/JahazielLem/attack-stix-data/contents/sparta-attack?ref=master";

/**
 * The expected file name format for versioned SPARTA STIX bundles.
 */
const SPARTA_FILE_PATTERN = /^sparta-attack-(\d+(?:\.\d+)*)\.json$/;

/**
 * Compares two dotted version strings.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function compareVersions(a, b) {
    const left = a.split(".").map(Number);
    const right = b.split(".").map(Number);
    const length = Math.max(left.length, right.length);
    for (let i = 0; i < length; i++) {
        const diff = (left[i] ?? 0) - (right[i] ?? 0);
        if (diff !== 0) {
            return diff;
        }
    }
    return 0;
}

/**
 * Resolves the latest versioned SPARTA STIX bundle from the GitHub API.
 * @returns {Promise<{ urls: string[], version: string }>}
 */
async function resolveSpartaSourceBundle() {
    const entries = await fetchJson(SPARTA_DIR_URL, {
        headers: {
            "User-Agent": "attack-flow-builder"
        }
    });

    const latest = entries
        .filter(entry => entry.type === "file" && SPARTA_FILE_PATTERN.test(entry.name))
        .map(entry => ({
            version: entry.name.match(SPARTA_FILE_PATTERN)?.[1] ?? "0",
            downloadUrl: entry.download_url
        }))
        .sort((a, b) => compareVersions(a.version, b.version))
        .at(-1);

    if (!latest?.downloadUrl) {
        throw new Error("Unable to resolve the latest SPARTA STIX bundle.");
    }

    return {
        urls: [latest.downloadUrl],
        version: latest.version
    };
}

/**
 * The STIX sources.
 */
export const STIX_SOURCES = {
    MitreAttack: [
        `${ATTACK_BASE_URL}/enterprise-attack/enterprise-attack-19.1.json`,
        `${ATTACK_BASE_URL}/ics-attack/ics-attack-19.1.json`,
        `${ATTACK_BASE_URL}/mobile-attack/mobile-attack-19.1.json`
    ],
    MitreAtlas: [
        "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/refs/heads/main/dist/stix-atlas.json"
    ],
    MitreF3: [
        "https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/refs/heads/main/public/f3-stix.json"
    ],
    MitreSparta: resolveSpartaSourceBundle
};

export { resolveSpartaSourceBundle };

/**
 * The D3FEND source.
 */
export const MITRE_DEFEND_URL = "https://d3fend.mitre.org/api/matrix-graph.json"
