import { fetchJson } from "./source_utils.mjs";

/**
 * @typedef {Object} SourceObject
 *  A Source Object.
 * @property {string} id
 *  The object's id.
 * @property {string} name
 *  The object's name.
 * @property {string} type
 *  The object's type.
 * @property {string} description
 *  The object's description.
 * @property {string} url
 *  The object's url.
 * @property {string} stixId
 *  The object's STIX id.
 * @property {boolean} deprecated
 *  True if the object has been deprecated, false otherwise.
 */

/**
 * A map that relates STIX types to source types.
 */
const STIX_TO_ATTACK = {
    "campaign": "campaign",
    "course-of-action": "mitigation",
    "intrusion-set": "group",
    "malware": "software",
    "tool": "software",
    "x-mitre-data-source": "data_source",
    "x-mitre-tactic": "tactic",
    "attack-pattern": "technique",
    "attack-subpattern": "subtechnique"
}

/**
 * MITRE's source identifiers.
 */
const MITRE_SOURCES = new Set([
    "mitre-attack",
    "mitre-ics-attack",
    "mitre-mobile-attack",
    "mitre-atlas",
    "mitre-f3",
    "sparta",
    "mitre-sparta-attack",
    "space-attack"
])

/**
 * SPARTA source identifiers.
 */
const SPARTA_SOURCES = new Set([
    "sparta",
    "mitre-sparta-attack",
    "space-attack"
]);

/**
 * Stable synthetic tactic metadata for SPARTA 3.x, which encodes tactics only
 * in kill chain phases instead of as standalone STIX objects.
 */
const SPARTA_TACTICS = new Map([
    ["Reconnaissance",      { id: "ST0001", stixId: "x-mitre-tactic--2d1b64b9-c681-405e-99de-b98aee9011fe" }],
    ["Resource Development",{ id: "ST0002", stixId: "x-mitre-tactic--5b6eff0e-7ac9-42c9-b0fb-088a4feadb03" }],
    ["Initial Access",      { id: "ST0003", stixId: "x-mitre-tactic--3756f0b5-9dd3-4fd0-9225-e3173eef2e10" }],
    ["Execution",           { id: "ST0004", stixId: "x-mitre-tactic--a685d777-f10c-4edc-b401-397a8e7e41f8" }],
    ["Persistence",         { id: "ST0005", stixId: "x-mitre-tactic--a4e870b4-df09-40b6-8740-62abcaa3ddf4" }],
    ["Defense Evasion",     { id: "ST0006", stixId: "x-mitre-tactic--ec717a52-de36-4597-b2ad-d9c9d120054a" }],
    ["Lateral Movement",    { id: "ST0007", stixId: "x-mitre-tactic--ebc70e48-3cad-4db4-be05-a62c42870e78" }],
    ["Exfiltration",        { id: "ST0008", stixId: "x-mitre-tactic--5721a603-bbbe-45cf-b838-c57abe7effd6" }],
    ["Impact",              { id: "ST0009", stixId: "x-mitre-tactic--c5e266e5-35cf-4cbb-81dc-81928672b06a" }]
]);

/**
 * Resolves the framework-specific type for a STIX object.
 * @param {Object} obj
 * @returns {string | undefined}
 */
function getSourceType(obj) {
    if (
        obj.type === "attack-pattern"
        && (
            obj.x_mitre_is_subtechnique
            || obj.x_sparta_is_subtechnique === true
            || obj.x_sparta_is_subtechnique === "True"
        )
    ) {
        return "subtechnique";
    }
    return STIX_TO_ATTACK[obj.type];
}


/**
 * Parses a source object from a STIX object.
 * @param {Object} obj
 *  The STIX object.
 * @returns {SourceObject | null}
 *  The parsed source object, if one can be derived.
 */
function parseStixToSourceObject(obj) {
    const type = getSourceType(obj);
    if (!type) {
        throw new Error(`Unsupported STIX source type '${obj.type}'.`);
    }

    const externalReferences = obj.external_references ?? [];
    const mitreRef = externalReferences.find(
        o => MITRE_SOURCES.has(o.source_name)
    );
    if (!mitreRef) {
        return null;
    }

    const inferredDomains = obj.x_mitre_domains
        ?? (SPARTA_SOURCES.has(mitreRef.source_name) ? ["sparta-attack"] : undefined);

    if (
        SPARTA_SOURCES.has(mitreRef.source_name)
        && ["technique", "subtechnique"].includes(type)
        && !(obj.kill_chain_phases?.length)
    ) {
        return null;
    }

    // Parse STIX id, name, and type directly
    let parse = {
        stixId: obj.id,
        name: obj.name,
        type,
        description: obj.description,
        external_references: externalReferences,
        platforms: obj.x_mitre_platforms,
        domains: inferredDomains
    }

    // Parse MITRE reference information
    parse.id = mitreRef.external_id;
    parse.url = mitreRef.url;

    // Parse MITRE shortname
    if (obj.x_mitre_shortname) {
        parse.shortname = obj.x_mitre_shortname;
    }

    // Parse kill-chain phases
    if (obj.kill_chain_phases) {
        parse.tactics = obj.kill_chain_phases.map(o => o.phase_name);
    }

    // Parse deprecation status
    parse.deprecated = (obj.x_mitre_deprecated || obj.revoked) ?? false;

    // Return
    return parse;
}

/**
 * Synthesizes tactic objects for SPARTA bundles that only encode tactics in
 * kill chain phases.
 * @param {Map<string, SourceObject>} objects
 * @returns {SourceObject[]}
 */
function synthesizeSpartaTactics(objects) {
    const phaseNames = new Set();
    let hasSpartaObjects = false;

    for (const obj of objects.values()) {
        if (obj.domains?.includes("sparta-attack")) {
            hasSpartaObjects = true;
        }
        for (const tactic of obj.tactics ?? []) {
            phaseNames.add(tactic);
        }
    }

    if (!hasSpartaObjects || phaseNames.size === 0) {
        return [];
    }

    return [...phaseNames]
        .map(name => {
            const meta = SPARTA_TACTICS.get(name);
            if (!meta) {
                return null;
            }
            return {
                stixId: meta.stixId,
                id: meta.id,
                shortname: name,
                name,
                type: "tactic",
                description: name,
                domains: ["sparta-attack"],
                deprecated: false
            };
        })
        .filter(Boolean);
}

/**
 * Parses a set of source objects from a STIX manifest.
 * @param {Object} data
 *  The STIX manifest.
 * @returns {SourceObject[]}
 *  The parsed source objects.
 */
function parseSourceObjectsFromManifest(data) {

    // Parse objects and relationships
    const relationships = new Map();
    let objects = new Map();
    for (let obj of data.objects) {
        if (obj.type === "relationship") {
            if (!relationships.has(obj.source_ref)) {
                relationships.set(obj.source_ref, new Set());
            }
            if (!relationships.has(obj.target_ref)) {
                relationships.set(obj.target_ref, new Set());
            }
            relationships.get(obj.source_ref).add(obj.target_ref);
            relationships.get(obj.target_ref).add(obj.source_ref);
            continue;
        }
        if (!(obj.type in STIX_TO_ATTACK)) {
            continue;
        }
        const parse = parseStixToSourceObject(obj);
        if (parse) {
            objects.set(parse.stixId, parse);
        }
    }

    if (![...objects.values()].some(obj => obj.type === "tactic")) {
        for (const tactic of synthesizeSpartaTactics(objects)) {
            objects.set(tactic.stixId, tactic);
        }
    }

    // Construct relationships
    for (const [object, relations] of relationships) {
        const source = objects.get(object);
        if (!source) {
            continue;
        }
        for (const relation of relations) {
            const target = objects.get(relation);
            if (!target) {
                continue;
            }
            const type = target.type;
            if (source[`${type}s`] === undefined) {
                source[`${type}s`] = [];
            }
            source[`${type}s`].push(target);
        }
    }

    // Collect tactics
    const tacticsMap = new Map();
    for(const tactic of objects.values()) {
        if(tactic.type !== "tactic") {
            continue;
        }
        tacticsMap.set(tactic.shortname, tactic);
    }

    // Assign tactics and techniques/subtechniques to each other
    for (const attackPattern of objects.values()) {
        if(!["technique", "subtechnique"].includes(attackPattern.type)) {
            continue;
        }
        const tactics = [];
        for(const tacticShortName of attackPattern.tactics ?? []) {
            // Add tactic to technique
            const tactic = tacticsMap.get(tacticShortName);
            if (!tactic) {
                continue;
            }
            tactics.push(tactic);
            // Add technique/subtechnique to tactic
            const field = attackPattern.type === "subtechnique"
                ? "subtechniques"
                : "techniques";
            if(!tactic[field]) {
                tactic[field] = [];
            }
            tactic[field].push(attackPattern);
        }
        attackPattern.tactics = tactics;
    }

    // Return catalog
    return [...objects.values()];

}

/**
 * Fetches source data from a set of STIX manifests.
 * @param  {...string} urls
 *  A list of STIX manifests specified by url.
 * @returns {Promise<Map<string, SourceObject>>}
 *  A Promise that resolves with the parsed source data.
 */
export async function fetchSourceData(...urls) {
    console.log("→ Downloading Source Data...");

    // Parse objects
    let catalog = new Map();
    for (let url of urls) {
        console.log(` → ${url.length > 70 ? '...' : ''}${url.substring(url.length - 70)}`);
        let objs = parseSourceObjectsFromManifest(await fetchJson(url));
        for (let obj of objs) {
            catalog.set(obj.stixId, obj);
        }
    }
    
    // Categorize catalog
    let types = new Map(
        [...new Set(Object.values(STIX_TO_ATTACK))].map(v => [v, []])
    );
    for(let obj of catalog.values()) {
        types.get(obj.type).push(obj);
    }

    // Return
    return types;

}
