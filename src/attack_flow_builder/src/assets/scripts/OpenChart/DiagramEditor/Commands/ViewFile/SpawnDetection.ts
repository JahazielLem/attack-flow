import { SpawnDefensiveObject, type DefensiveSourceObject } from "./SpawnDefensiveObject";
import { sourceData } from "@/assets/configuration/AttackFlowTemplates/SourceEnumeration";
import type { DiagramViewFile } from "@OpenChart/DiagramView";

type DetectionSourceObject = DefensiveSourceObject & { type: "detection" };

export class SpawnDetection extends SpawnDefensiveObject {

    /**
     * Spawns an Attack Flow detection in a diagram file.
     * @param file
     *  The diagram file.
     * @param detectionId
     *  The detection source id.
     * @param x
     *  The detection's x-coordinate.
     * @param y
     *  The detection's y-coordinate.
     * @param fromCorner
     *  Whether to position the detection from its top-left corner or its center.
     *  (Default: `false`)
     */
    constructor(
        file: DiagramViewFile,
        detectionId: string,
        x: number,
        y: number,
        fromCorner: boolean = false
    ) {
        super(file, getDetectionSourceObject(detectionId), x, y, fromCorner);
    }

}

function getDetectionSourceObject(sourceId: string): DetectionSourceObject {
    const sourceObject = sourceData.detections[sourceId];
    if (!sourceObject) {
        throw new Error(`Unknown detection id '${sourceId}'.`);
    }
    return sourceObject as DetectionSourceObject;
}
