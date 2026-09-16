import { SpawnDefensiveObject, type DefensiveSourceObject } from "./SpawnDefensiveObject";
import { sourceData } from "@/assets/configuration/AttackFlowTemplates/SourceEnumeration";
import type { DiagramViewFile } from "@OpenChart/DiagramView";

type MitigationSourceObject = DefensiveSourceObject & { type: "mitigation" };

export class SpawnMitigation extends SpawnDefensiveObject {

    /**
     * Spawns an Attack Flow mitigation in a diagram file.
     * @param file
     *  The diagram file.
     * @param mitigationId
     *  The mitigation source id.
     * @param x
     *  The mitigation's x-coordinate.
     * @param y
     *  The mitigation's y-coordinate.
     * @param fromCorner
     *  Whether to position the mitigation from its top-left corner or its center.
     *  (Default: `false`)
     */
    constructor(
        file: DiagramViewFile,
        mitigationId: string,
        x: number,
        y: number,
        fromCorner: boolean = false
    ) {
        super(file, getMitigationSourceObject(mitigationId), x, y, fromCorner);
    }

}

function getMitigationSourceObject(sourceId: string): MitigationSourceObject {
    const sourceObject = sourceData.mitigations[sourceId];
    if (!sourceObject) {
        throw new Error(`Unknown mitigation id '${sourceId}'.`);
    }
    return sourceObject as MitigationSourceObject;
}
