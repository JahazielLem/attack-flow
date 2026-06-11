import AttackEnums from "../AttackFlowTemplates/MitreAttack";
import AtlasEnums from "../AttackFlowTemplates/MitreAtlas";
import DefendEnums from "../AttackFlowTemplates/MitreDefend";
import F3Enums from "../AttackFlowTemplates/MitreF3";
import SpartaEnums from "../AttackFlowTemplates/MitreSparta";

interface SourceEnums {
    tactics: string[][];
    techniques: string[][];
    subtechniques: string[][];
    relationships: string[][];
    stixIds: Record<string, string>;
    version?: string;
}

const sources: SourceEnums[] = [
    AttackEnums,
    AtlasEnums,
    DefendEnums,
    F3Enums,
    SpartaEnums
];

const enums: SourceEnums = sources.reduce<SourceEnums>((acc, src) => {
    acc.tactics.push(...src.tactics);
    acc.techniques.push(...src.techniques);
    acc.subtechniques.push(...src.subtechniques);
    acc.relationships.push(...src.relationships);
    acc.stixIds = { ...src.stixIds, ...acc.stixIds };
    acc.version ??= src.version;

    return acc;
}, {
    tactics: [],
    techniques: [],
    subtechniques: [],
    relationships: [],
    stixIds: {},
    version: undefined
});

export default enums;
