import { mkdirSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { STIX_SOURCES } from "./sources.mjs";
import { parseSourceObjectsFromManifest } from "./download_stix_source.mjs";
import { EXPORT_KEY, fetchJson } from "./source_utils.mjs";

const ENUM_DIR = "../src/assets/configuration/AttackFlowTemplates";
const DOMAIN_PREFIXES = { MitreAtlas: "ATL", MitreF3: "F3", MitreSparta: "SPA", SpaceShield: "SSH" };
// SPACE-SHIELD reuses ATT&CK tactic IDs; keep its choices and STIX references separate.
const ID_PREFIXES = { MitreF3: "F3", SpaceShield: "SSH" };
const SOURCE_NAMES = { MitreAttack: "ATTACK", MitreAtlas: "ATLAS", MitreF3: "F3", MitreSparta: "SPARTA", SpaceShield: "SPACE-SHIELD" };
const WIKI_NAMES = { MitreAttack: "MITRE ATT&CK", MitreAtlas: "MITRE ATLAS", MitreF3: "MITRE F3", MitreSparta: "SPARTA", SpaceShield: "SPACE-SHIELD" };

const sourceId = (obj, fileName) => {
    // SPARTA embeds D3FEND countermeasures with different STIX object types/IDs.
    const prefix = fileName === "MitreSparta" && obj.type === "mitigation" && obj.id.startsWith("D3-")
        ? "SPA" : ID_PREFIXES[fileName];
    return prefix ? `${prefix}.${obj.id}` : obj.id;
};
const matrixLabel = (obj, fileName) => DOMAIN_PREFIXES[fileName]
    ?? obj.domains?.map(domain => domain.substring(0, 3).toUpperCase()).join(", ") ?? "";
const sortRecord = record => Object.fromEntries(Object.entries(record).sort(([a], [b]) => a.localeCompare(b)));

/** Convert parsed STIX objects into the builder catalog and the separately loaded wiki. */
export function generateSourceEnumeration(objects, fileName, metadata = {}) {
    const active = objects.filter(obj => !obj.deprecated);
    const byStixId = new Map(active.map(obj => [obj.stixId, obj]));
    const records = { tactics: {}, techniques: {}, subtechniques: {}, mitigations: {}, detections: {} };
    const fields = { tactic: "tactics", technique: "techniques", subtechnique: "subtechniques", mitigation: "mitigations", detection: "detections" };
    for (const obj of active) {
        const field = fields[obj.type];
        if (!field) continue;
        const id = sourceId(obj, fileName);
        const record = {
            id, name: obj.name, label: `[${matrixLabel(obj, fileName)}] ${id} ${obj.name}`,
            type: obj.type, source: SOURCE_NAMES[fileName], domains: obj.domains,
            stixId: obj.stixId, url: obj.url
        };
        if (obj.type === "detection") record.log_sources = obj.log_sources ?? [];
        records[field][id] = record;
        // Upstream enrichment and publishing address every attack-pattern as a technique.
        if (obj.type === "subtechnique") records.techniques[id] = record;
    }
    const relationships = { tacticTechniques: [], techniqueSubtechniques: [], techniqueMitigations: [], techniqueDetections: [] };
    const seen = new Set();
    const add = (field, row) => {
        const key = `${field}:${JSON.stringify(row)}`;
        if (!seen.has(key)) { seen.add(key); relationships[field].push(row); }
    };
    const patterns = active.filter(obj => ["technique", "subtechnique"].includes(obj.type));
    for (const obj of patterns) {
        const techniqueId = sourceId(obj, fileName);
        for (const tactic of obj.tactics ?? []) {
            if (!tactic.deprecated && byStixId.has(tactic.stixId)) {
                add("tacticTechniques", { tacticId: sourceId(tactic, fileName), techniqueId });
            }
        }
        if (obj.type === "subtechnique") {
            for (const parent of obj.techniques ?? []) {
                if (!parent.deprecated && byStixId.has(parent.stixId)) {
                    add("techniqueSubtechniques", { techniqueId: sourceId(parent, fileName), subtechniqueId: techniqueId });
                }
            }
        }
    }
    for (const obj of active) {
        const isMitigation = obj.type === "mitigation";
        if (!isMitigation && obj.type !== "detection") continue;
        for (const rel of obj.stixRelationships ?? []) {
            if (rel.relationshipType !== (isMitigation ? "mitigates" : "detects")) continue;
            const target = byStixId.get(rel.targetRef);
            if (!target || !["technique", "subtechnique"].includes(target.type)) continue;
            add(isMitigation ? "techniqueMitigations" : "techniqueDetections", {
                techniqueId: sourceId(target, fileName),
                [isMitigation ? "mitigationId" : "detectionId"]: sourceId(obj, fileName)
            });
        }
    }
    const linked = obj => ({ id: sourceId(obj, fileName), stixId: obj.stixId, name: obj.name, description: obj.description ?? "", url: obj.url });
    const wiki = patterns.map(obj => ({
        ...linked(obj), model: WIKI_NAMES[fileName], matrix: matrixLabel(obj, fileName), type: obj.type,
        label: `[${matrixLabel(obj, fileName)}] ${sourceId(obj, fileName)} ${obj.name}`,
        platforms: obj.platforms ?? [],
        tactics: (obj.tactics ?? []).filter(t => !t.deprecated).map(t => ({ id: sourceId(t, fileName), name: t.name, shortname: t.shortname ?? t.name })),
        parentTechniques: obj.type === "subtechnique" ? (obj.techniques ?? []).filter(t => !t.deprecated).map(linked) : [],
        mitigations: (obj.mitigations ?? []).filter(t => !t.deprecated).map(linked),
        externalReferences: (obj.external_references ?? []).filter(ref => ref.url || ref.external_id)
            .map(ref => ({ source: ref.source_name, id: ref.external_id, url: ref.url }))
    })).sort((a, b) => a.label.localeCompare(b.label));
    return {
        data: { ...Object.fromEntries(Object.entries(records).map(([key, value]) => [key, sortRecord(value)])), relationships, ...metadata },
        wiki: { wiki }
    };
}

/** Metadata describes the framework collection, never the STIX specification version. */
export function getBundleMetadata(bundles, config) {
    const collections = bundles.flatMap(bundle => bundle.objects.filter(obj => ["x-mitre-collection", "x-sparta-collection"].includes(obj.type)));
    const versions = [...new Set(collections.map(obj => obj.x_sparta_version ?? obj.x_mitre_version).filter(Boolean).map(v => v.replace(/^v/, "")))];
    const modified = bundles.flatMap(bundle => bundle.objects.map(obj => obj.modified).filter(Boolean)).sort().at(-1);
    return {
        version: versions.join(" / ") || modified?.slice(0, 10) || "unversioned",
        modified,
        sourceUrls: config.urls,
        documentationUrl: config.documentationUrl,
        stixVersion: "2.1"
    };
}

export default async function updateApplicationSourceEnums(fileName) {
    const config = STIX_SOURCES[fileName];
    if (!config) throw new Error(`Unknown framework '${fileName}'.`);
    const base = dirname(fileURLToPath(import.meta.url));
    const bundles = [];
    for (const url of config.urls) {
        console.log(`→ Downloading ${url}`);
        const bundle = await fetchJson(url);
        if (bundle.type !== "bundle" || !Array.isArray(bundle.objects)) throw new Error(`Invalid STIX bundle from ${url}`);
        bundles.push(bundle);
    }
    // Parse domains independently: several ATT&CK objects belong to multiple matrices.
    const catalog = new Map();
    for (const bundle of bundles) {
        for (const obj of parseSourceObjectsFromManifest(bundle)) {
            const previous = catalog.get(obj.stixId);
            if (previous) {
                obj.domains = [...new Set([...(previous.domains ?? []), ...(obj.domains ?? [])])];
                if (obj.tactics) obj.tactics = [...new Map([...(previous.tactics ?? []), ...obj.tactics].map(t => [t.stixId, t])).values()];
                obj.stixRelationships = [...(previous.stixRelationships ?? []), ...(obj.stixRelationships ?? [])];
            }
            catalog.set(obj.stixId, obj);
        }
    }
    const result = generateSourceEnumeration([...catalog.values()], fileName, getBundleMetadata(bundles, config));
    for (const [suffix, data] of [["", result.data], ["Wiki", result.wiki]]) {
        writeFileSync(resolve(base, `${ENUM_DIR}/${fileName}${suffix}.ts`), `/* eslint-disable */
export const ${EXPORT_KEY} = ${JSON.stringify(data)};

export default ${EXPORT_KEY};
`);
    }
    // Keep the legacy SPARTA snapshot current; the application consumes generated catalogs.
    if (fileName === "MitreSparta" || fileName === "SpaceShield") {
        const dataDir = resolve(base, "../data");
        mkdirSync(dataDir, { recursive: true });
        writeFileSync(resolve(dataDir, fileName === "MitreSparta" ? "sparta-attack.json" : "space-attack.json"), JSON.stringify(bundles[0], null, 2) + "\n");
    }
    console.log(`→ ${fileName} ${result.data.version}: updated catalog and wiki.`);
}
