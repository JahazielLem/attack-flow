import { sourceData, type LogSource } from "./SourceEnumeration";



/**

 * Returns catalog log sources for a detection strategy.

 */

export function getCatalogLogSources(

    detectionId: string | null | undefined

): LogSource[] {

    if (!detectionId) {

        return [];

    }



    return sourceData.detections[detectionId]?.log_sources ?? [];

}
