import { writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { STIX_SOURCES } from "./sources.mjs";
import { fileURLToPath } from 'url';
import { fetchSourceData } from "./download_stix_source.mjs";
import { EXPORT_KEY } from "./source_utils.mjs";

/**
 * The enumeration file's directory.
 */
const ENUM_DIR  = `../src/assets/configuration/AttackFlowTemplates`;

/**
 * The domain prefix for tactics and techniques from sources without this information.
 */
const DOMAIN_PREFIXES = {
    MitreAtlas: "ATL",
    MitreF3: "F3",
    MitreSparta: "SPA"
}

/**
 * The ID prefix for tactics and techniques from sources without this information.
 */
const ID_PREFIXES = {
    MitreF3: "F3"
}

/**
 * Human-facing source names for wiki entries.
 */
const SOURCE_NAMES = {
    MitreAttack: "MITRE ATT&CK",
    MitreAtlas: "MITRE ATLAS",
    MitreF3: "MITRE F3",
    MitreSparta: "SPARTA"
}

/**
 * JavaScript variable regex.
 */
const JS_VAR_REGEX = /^[a-z_$][a-z0-9_$]*$/i;

/**
 * Updates the specified enum file.
 * @param {string} fileName
 *  The enum file's name.
 */
export default async function updateApplicationSourceEnums(fileName) {
    const path = resolve(dirname(fileURLToPath(import.meta.url)), `${ ENUM_DIR }/${ fileName }.ts`);
    const wikiPath = resolve(dirname(fileURLToPath(import.meta.url)), `${ ENUM_DIR }/${ fileName }Wiki.ts`);

    // Validate export key
    if(!JS_VAR_REGEX.test(EXPORT_KEY)) {
        throw new Error(`Export key '${ EXPORT_KEY }' is not a valid variable name.`);
    }

    // Collect data
    const sourceConfig = STIX_SOURCES[fileName];
    const sourceData = typeof sourceConfig === "function"
        ? await sourceConfig()
        : sourceConfig;
    const urls = Array.isArray(sourceData)
        ? sourceData
        : sourceData.urls;
    const types = await fetchSourceData(...urls);
    const version = Array.isArray(sourceData)
        ? undefined
        : sourceData.version;

    console.log(`→ Generating enumerations file...`);

    // Organize tactics
    const tactics = [];
    const stixIds = {};
    for(const tact of types.get("tactic")) {
        if(tact.deprecated) {
            continue;
        }

        const matrix = tact.domains ? tact.domains.map(
            o => o.substring(0,3).toLocaleUpperCase()
        ).join(", ") : DOMAIN_PREFIXES[fileName];

        const tacticId = ID_PREFIXES[fileName]
            ? `${ID_PREFIXES[fileName]}.${tact.id}`
            : tact.id;

        tactics.push([tacticId, `[${matrix}] ${tacticId} ${tact.name}`]);
        stixIds[tacticId] = tact.stixId;
    }
    tactics.sort(([a],[b]) => a.localeCompare(b));

    // Organize techniques
    const techniques = [];
    for(const tech of types.get("technique")) {
        if(tech.deprecated) {
            continue;
        }
        const matrix = tech.domains ? tech.domains.map(
            o => o.substring(0,3).toLocaleUpperCase()
        ).join(", ") : DOMAIN_PREFIXES[fileName];

        const techniqueId = ID_PREFIXES[fileName]
            ? `${ID_PREFIXES[fileName]}.${tech.id}`
            : tech.id;

        techniques.push([techniqueId, `[${matrix}] ${techniqueId} ${tech.name}`]);

        stixIds[techniqueId] = tech.stixId;
    }
    techniques.sort(([a],[b]) => a.localeCompare(b));

    // Organize subtechniques
    const subtechniques = [];
    for(const tech of types.get("subtechnique") ?? []) {
        if(tech.deprecated) {
            continue;
        }
        const matrix = tech.domains ? tech.domains.map(
            o => o.substring(0,3).toLocaleUpperCase()
        ).join(", ") : DOMAIN_PREFIXES[fileName];

        const techniqueId = ID_PREFIXES[fileName]
            ? `${ID_PREFIXES[fileName]}.${tech.id}`
            : tech.id;

        subtechniques.push([techniqueId, `[${matrix}] ${techniqueId} ${tech.name}`]);

        stixIds[techniqueId] = tech.stixId;
    }
    subtechniques.sort(([a],[b]) => a.localeCompare(b));

    // Organize valid pairwise relationships
    const relationships = [];
    const relationKeys = new Set();
    const addRelationship = (leftType, leftId, rightType, rightId) => {
        const key = `${leftType}:${leftId}|${rightType}:${rightId}`;
        if (relationKeys.has(key)) {
            return;
        }
        relationKeys.add(key);
        relationships.push([leftType, leftId, rightType, rightId]);
    };

    for(const tech of types.get("technique")) {
        if(tech.deprecated) {
            continue;
        }
        const techniqueId = ID_PREFIXES[fileName]
            ? `${ID_PREFIXES[fileName]}.${tech.id}`
            : tech.id;

        for (const tact of tech.tactics ?? []) {
            const tacticId = ID_PREFIXES[fileName]
                ? `${ID_PREFIXES[fileName]}.${tact.id}`
                : tact.id;
            addRelationship("tactic", tacticId, "technique", techniqueId);
        }
    }

    for(const subtech of types.get("subtechnique") ?? []) {
        if(subtech.deprecated) {
            continue;
        }
        const subtechniqueId = ID_PREFIXES[fileName]
            ? `${ID_PREFIXES[fileName]}.${subtech.id}`
            : subtech.id;

        for (const tactic of subtech.tactics ?? []) {
            const tacticId = ID_PREFIXES[fileName]
                ? `${ID_PREFIXES[fileName]}.${tactic.id}`
                : tactic.id;
            addRelationship("tactic", tacticId, "subtechnique", subtechniqueId);
        }

        for (const technique of subtech.techniques ?? []) {
            const techniqueId = ID_PREFIXES[fileName]
                ? `${ID_PREFIXES[fileName]}.${technique.id}`
                : technique.id;
            addRelationship("technique", techniqueId, "subtechnique", subtechniqueId);
        }
    }

    // Organize searchable wiki data
    const wiki = [];
    const formatId = (obj) => ID_PREFIXES[fileName]
        ? `${ID_PREFIXES[fileName]}.${obj.id}`
        : obj.id;
    const formatMatrix = (obj) => obj.domains
        ? obj.domains.map(o => o.substring(0,3).toLocaleUpperCase()).join(", ")
        : DOMAIN_PREFIXES[fileName];
    const formatReferences = (obj) => (obj.external_references ?? [])
        .filter(ref => ref.url || ref.external_id)
        .map(ref => ({
            source: ref.source_name,
            id: ref.external_id,
            url: ref.url
        }));
    const formatLinkedObject = (obj) => ({
        id: formatId(obj),
        stixId: obj.stixId,
        name: obj.name,
        description: obj.description ?? "",
        url: obj.url
    });
    const formatTactics = (obj) => (obj.tactics ?? [])
        .filter(tactic => !tactic.deprecated)
        .map(tactic => ({
            id: formatId(tactic),
            name: tactic.name,
            shortname: tactic.shortname ?? tactic.name
        }));
    const formatMitigations = (obj) => (obj.mitigations ?? [])
        .filter(mitigation => !mitigation.deprecated)
        .map(formatLinkedObject);

    for (const obj of [
        ...(types.get("technique") ?? []),
        ...(types.get("subtechnique") ?? [])
    ]) {
        if (obj.deprecated) {
            continue;
        }

        const id = formatId(obj);
        const matrix = formatMatrix(obj);
        wiki.push({
            id,
            stixId: obj.stixId,
            model: SOURCE_NAMES[fileName] ?? fileName,
            matrix,
            type: obj.type,
            name: obj.name,
            label: `[${matrix}] ${id} ${obj.name}`,
            description: obj.description ?? "",
            url: obj.url,
            platforms: obj.platforms ?? [],
            tactics: formatTactics(obj),
            parentTechniques: (obj.techniques ?? [])
                .filter(technique => !technique.deprecated)
                .map(formatLinkedObject),
            mitigations: formatMitigations(obj),
            externalReferences: formatReferences(obj)
        });
    }
    wiki.sort((a, b) => a.label.localeCompare(b.label));

    // Generate enums file
    let file = "";
    file += "/* eslint-disable */\n";
    file += `export const ${ EXPORT_KEY } = `;
    file += JSON.stringify({ tactics, techniques, subtechniques, relationships, stixIds, version });
    file += `;\n\nexport default ${ EXPORT_KEY };\n`
    writeFileSync(path, file);

    // Generate wiki file separately so the main enum bundle stays small.
    file = "";
    file += "/* eslint-disable */\n";
    file += `export const ${ EXPORT_KEY } = `;
    file += JSON.stringify({ wiki });
    file += `;\n\nexport default ${ EXPORT_KEY };\n`
    writeFileSync(wikiPath, file);

    // Done
    console.log("\nSource enumerations updated successfully.\n");

}
