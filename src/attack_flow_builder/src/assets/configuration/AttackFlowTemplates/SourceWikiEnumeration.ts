import AttackWikiEnums from "../AttackFlowTemplates/MitreAttackWiki";
import AtlasWikiEnums from "../AttackFlowTemplates/MitreAtlasWiki";
import DefendWikiEnums from "../AttackFlowTemplates/MitreDefendWiki";
import F3WikiEnums from "../AttackFlowTemplates/MitreF3Wiki";
import SpartaWikiEnums from "../AttackFlowTemplates/MitreSpartaWiki";

interface SourceWikiEnums {
    wiki: TtpWikiEntry[];
}

export type TtpWikiLink = {
    id: string;
    stixId?: string;
    name: string;
    description?: string;
    url?: string;
    shortname?: string;
};

export type TtpWikiExternalReference = {
    source?: string;
    id?: string;
    url?: string;
};

export type TtpWikiEntry = {
    id: string;
    stixId?: string;
    model: string;
    matrix: string;
    type: string;
    name: string;
    label: string;
    description: string;
    url?: string;
    platforms: string[];
    tactics: TtpWikiLink[];
    parentTechniques: TtpWikiLink[];
    mitigations: TtpWikiLink[];
    externalReferences: TtpWikiExternalReference[];
};

const sources: SourceWikiEnums[] = [
    AttackWikiEnums,
    AtlasWikiEnums,
    DefendWikiEnums,
    F3WikiEnums,
    SpartaWikiEnums
];

const enums: SourceWikiEnums = sources.reduce<SourceWikiEnums>((acc, src) => {
    acc.wiki.push(...(src.wiki ?? []));

    return acc;
}, {
    wiki: []
});

export default enums;
