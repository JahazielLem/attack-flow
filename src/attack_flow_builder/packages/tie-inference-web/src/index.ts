import { TechniqueInferenceEngine } from "./tie/TechniqueInferenceEngine/TechniqueInferenceEngine";
import { RemoteModelSource } from "./tie/TechniqueInferenceEngine/DataSource/TrainedModel/RemoteModelSource";
import type { EnrichmentFile } from "./tie/TechniqueInferenceEngine/DataSource/EnrichmentFile/EnrichmentFile";

// Minimal structural type compatible with the engine’s DataSource<T>
type DataSource<T> = {
    cachingEnabled: boolean;
    preload(): Promise<void>;
    dumpCache(): void;
    getData(): Promise<T>;
};

export type TiePrediction = { id: string; score: number; rank: number };
export type TieEngine = {
    warmup(): Promise<void>;
    predict(ids: Iterable<string>): Promise<TiePrediction[]>;
};

export async function createEngine(
    npzUrl: string,
    enrichmentUrl?: string,
    cache: boolean = true
): Promise<TieEngine> {
    const modelSource = new RemoteModelSource(npzUrl, cache);

    let enrichmentSource: DataSource<EnrichmentFile>;
    if (enrichmentUrl) {
        const { RemoteEnrichmentSource } = await import(
            "./tie/TechniqueInferenceEngine/DataSource/EnrichmentFile/RemoteEnrichmentSource"
        );
        enrichmentSource = new (RemoteEnrichmentSource as any)(enrichmentUrl, cache);
    } else {
        // Stub enrichment to keep the package logic-only and client-side
        enrichmentSource = {
            cachingEnabled: false,
            async preload() { },
            dumpCache() { },
            async getData() {
                return { domain: "N/A", version: "N/A", techniques: {} } as any;
            },
        };
    }

    const engine = new TechniqueInferenceEngine(
        modelSource as any,
        enrichmentSource as any
    );

    return {
        async warmup() {
            await engine.warmup();
        },
        async predict(ids: Iterable<string>) {
            const results = await engine.predictNewReport(new Set<string>(ids as any));
            const arr: TiePrediction[] = [];
            for (const [id, info] of results.entries()) {
                arr.push({ id, score: info.score, rank: info.rank });
            }
            return arr;
        },
    };
}
