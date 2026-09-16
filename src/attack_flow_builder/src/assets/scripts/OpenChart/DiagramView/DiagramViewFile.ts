import { ManualLayoutEngine } from "./DiagramLayoutEngine";
import { Canvas, DiagramModelFile, DiagramObjectSerializer } from "@OpenChart/DiagramModel";
import type { CameraLocation } from "./CameraLocation";
import type { DiagramViewExport } from "./DiagramViewExport";
import type { DiagramLayoutEngine } from "./DiagramLayoutEngine";
import { BlockView } from "./DiagramObjectView";
import type { CanvasView, DiagramObjectView } from "./DiagramObjectView";
import type { DiagramTheme, DiagramObjectViewFactory } from "./DiagramObjectViewFactory";

export class DiagramViewFile extends DiagramModelFile {

    /**
     * The clear vertical space preserved between assets attached to one action.
     */
    private static readonly ACTION_ASSET_CLEARANCE = 50;

    /**
     * The file's camera location.
     */
    public readonly camera: CameraLocation;

    /**
     * The file's canvas.
     */
    declare readonly canvas: CanvasView;

    /**
     * The file's object factory.
     */
    declare readonly factory: DiagramObjectViewFactory;


    /**
     * Creates a new {@link DiagramModelFile}.
     * @param factory
     *  The file's object factory.
     */
    constructor(factory: DiagramObjectViewFactory);

    /**
     * Imports a {@link DiagramModelFile}.
     * @param factory
     *  The file's object factory.
     * @param diagram
     *  The file to import.
     */
    constructor(factory: DiagramObjectViewFactory, diagram?: DiagramViewExport);
    constructor(factory: DiagramObjectViewFactory, diagram?: DiagramViewExport) {
        // Create / Import
        super(factory, diagram);
        // Calculate layout
        this.canvas.calculateLayout();
        // Run layout engine
        if (diagram && !(diagram instanceof Canvas) && diagram.layout) {
            new ManualLayoutEngine(diagram.layout).run([this.canvas]);
        }
        // Set camera
        this.camera = diagram?.camera ?? { x: 0, y: 0, k: 1 };
    }


    /**
     * Applies a new theme to the diagram.
     * @param theme
     *  The theme to apply.
     */
    public async applyTheme(theme: DiagramTheme) {
        // Replace factory theme
        this.factory.theme = theme;
        // Restyle diagram
        this.factory.restyleDiagramObject([this.canvas]);
    }

    /**
     * Runs the specified layout engine on the file's diagram.
     * @param layout
     *  The layout engine to apply.
     */
    public runLayout(layout: DiagramLayoutEngine) {
        layout.run([this.canvas]);
    }

    /**
     * Vertically center direct support-card children of each action using their
     * rendered dimensions. This includes typed STIX cards (file, software,
     * process, etc.), not only generic assets.
     */
    public compactActionAssetStacks(): void {
        const assetsByAction = new Map<BlockView, Set<BlockView>>();
        const actionCountByAsset = new Map<BlockView, number>();

        for (const line of this.canvas.lines) {
            const source = line.sourceObject;
            const target = line.targetObject;
            if (source?.id !== "action" || !(target instanceof BlockView) || !DiagramViewFile.isActionSupportCard(target)) {
                continue;
            }

            const action = source as BlockView;
            const asset = target as BlockView;
            const assets = assetsByAction.get(action) ?? new Set<BlockView>();
            assets.add(asset);
            assetsByAction.set(action, assets);
            actionCountByAsset.set(asset, (actionCountByAsset.get(asset) ?? 0) + 1);
        }

        for (const [action, assetSet] of assetsByAction) {
            const assets = [...assetSet]
                .filter(asset => actionCountByAsset.get(asset) === 1)
                .sort((left, right) => left.face.boundingBox.yMid - right.face.boundingBox.yMid);
            if (assets.length < 2) {
                continue;
            }

            const stackHeight = assets.reduce(
                (total, asset) => total + asset.face.boundingBox.height,
                0
            ) + DiagramViewFile.ACTION_ASSET_CLEARANCE * (assets.length - 1);
            let nextTop = action.face.boundingBox.yMid - stackHeight / 2;

            for (const asset of assets) {
                const bounds = asset.face.boundingBox;
                const nextCenter = nextTop + bounds.height / 2;
                asset.moveBy(0, nextCenter - bounds.yMid);
                nextTop += bounds.height + DiagramViewFile.ACTION_ASSET_CLEARANCE;
            }
        }

        this.canvas.calculateLayout();
    }

    private static isActionSupportCard(block: BlockView): boolean {
        return !new Set([
            "action",
            "condition",
            "AND_operator",
            "OR_operator"
        ]).has(block.id);
    }

    /**
     * Set camera position to the average position of blocks in the diagram.
     * Set k value to 0.25.
     */
    public centerAndZoomCamera(): void {
        const totalPosition = { x: 0, y: 0 };
        for (const block of this.canvas.blocks) {
            totalPosition.x += block.x;
            totalPosition.y += block.y;
        }
        const numBlocks = this.canvas.blocks.length;
        const averagePosition = { x: 0, y:0 };
        if (numBlocks > 0) {
            averagePosition.x = totalPosition.x / numBlocks;
            averagePosition.y = totalPosition.y / numBlocks;
        }
        this.camera.x = averagePosition.x;
        this.camera.y = averagePosition.y;
        this.camera.k = 0.25;
    }

    /**
     * Clones the {@link DiagramViewFile}.
     * @param match
     *  A predicate which is applied to each child of the canvas. If the
     *  predicate returns false, the child is excluded from the clone.
     */
    public clone(match?: (obj: DiagramObjectView) => boolean): DiagramViewFile {

        // Clone canvas
        const instanceMap = new Map<string, string>();
        const canvas = this.canvas.clone(this.canvas.instance, instanceMap, match);

        // Calculate layout
        canvas.calculateLayout();

        // Apply existing layout to clone
        const existingLayout = ManualLayoutEngine.generatePositionMap([this.canvas]);
        const remappedLayout = Object.fromEntries(
            Object.entries(existingLayout).map(
                ([i, p]) => [instanceMap.get(i)!, p]
            )
        );
        new ManualLayoutEngine(remappedLayout).run([canvas]);

        /**
         * Developer's Note:
         * You may be wondering why we generate a new position map from `canvas`
         * instead of simply using `remappedLayout`.
         *
         * Simply put, `layout` and `remappedLayout` are not always equivalent.
         *
         * For example, `remappedLayout` excludes the positions of latches
         * linked to block anchors. Those same latches may be unlinked in
         * `canvas` if their blocks were omitted from the clone.
         *
         * To ensure these latches are included in the position map, we have to
         * generate a new position map directly from `canvas`.
         */

        // Calculate final layout
        const layout = ManualLayoutEngine.generatePositionMap([canvas]);

        // Return clone
        return new DiagramViewFile(
            this.factory,
            {
                schema  : this.factory.id,
                theme   : this.factory.theme.id,
                objects : DiagramObjectSerializer.exportObjects([canvas]),
                layout  : layout,
                camera  : { ...this.camera }
            }
        );

    }

    /**
     * Exports the file.
     * @returns
     *  The serialized file.
     */
    public toExport(): DiagramViewExport {
        const model = super.toExport();
        return {
            schema  : model.schema,
            objects : model.objects,
            layout  : ManualLayoutEngine.generatePositionMap([this.canvas]),
            camera  : this.camera
        };
    }

}
