import { SpawnObject } from "./SpawnObject";
import { StringProperty, TTPTupleProperty } from "@OpenChart/DiagramModel";
import type { DiagramObjectView, DiagramViewFile } from "@OpenChart/DiagramView";
import { getTechniqueNameFromLabel } from "@/assets/configuration/AttackFlowTemplates/TTPFrameworkConstants";

export class SpawnAction extends SpawnObject {

    /**
     * The action's technique id.
     */
    public readonly techniqueId: string;

    /**
     * The action's tactic id.
     */
    public readonly tacticId: string;


    /**
     * Spawns an Attack Flow action in a diagram file.
     * @param file
     *  The diagram file.
     * @param techniqueId
     *  The action's technique id.
     * @param x
     *  The action's x-coordinate.
     * @param y
     *  The action's y-coordinate.
     * @param fromCorner
     *  Whether to position the action from its top-left corner or its center.
     *  (Default: `false`)
     */
    constructor(file: DiagramViewFile, techniqueId: string, x: number, y: number, fromCorner: boolean = false) {
        super(file, techniqueId, x, y, fromCorner);
        this.techniqueId = techniqueId;
        this.tacticId = this.getTacticId();
    }

    /**
     * Creates the action to spawn.
     * @param file
     *  The diagram file.
     * @returns
     *  The action to spawn.
     */
    protected override createObject(file: DiagramViewFile, _techniqueId: string): DiagramObjectView {
        return file.factory.createNewDiagramObject("action");
    }

    /**
     * Configures the action before layout and placement.
     * @param _object
     *  The action to spawn.
     * @param techniqueId
     *  The action's technique id.
     */
    protected override configureObject(object: DiagramObjectView, techniqueId: string): void {
        this.configureTTP(object, techniqueId);
    }

    /**
     * Configures the action's TTP mapping.
     * @param object
     *  The action to spawn.
     * @param techniqueId
     *  The technique id.
     */
    private configureTTP(object: DiagramObjectView, techniqueId: string): void {
        const ttp = object.properties.get("ttp", TTPTupleProperty);
        if (!ttp) {
            throw new Error("Action template is missing a TTP mapping property.");
        }
        const tactic = ttp.get("tactic", StringProperty);
        const technique = ttp.get("technique", StringProperty);
        if (!tactic || !technique) {
            throw new Error("Action TTP mapping is missing a tactic or technique field.");
        }
        if (!technique.options?.value.has(techniqueId)) {
            throw new Error(`Unknown technique id '${techniqueId}'.`);
        }
        // Setting the technique refreshes the tuple's valid tactic options.
        technique.setValue(techniqueId);

        const tacticId = tactic.value ?? this.resolveTacticId(ttp, tactic, techniqueId);
        tactic.setValue(tacticId);
        this.setDefaultName(object, technique, techniqueId);
    }

    /**
     * Resolves the first valid tactic id for a technique.
     * @param ttp
     *  The action's TTP tuple.
     * @param tactic
     *  The tuple's tactic property.
     * @param techniqueId
     *  The technique id.
     * @returns
     *  The resolved tactic id.
     */
    private resolveTacticId(
        ttp: TTPTupleProperty,
        tactic: StringProperty,
        techniqueId: string
    ): string {
        const validTactics = ttp.validPropValues?.get("tactic");
        if (!validTactics?.size) {
            throw new Error(`Technique id '${techniqueId}' has no associated tactic.`);
        }
        for (const tacticId of tactic.options?.value.keys() ?? []) {
            if (validTactics.has(tacticId)) {
                return tacticId;
            }
        }
        return [...validTactics][0];
    }

    /**
     * Gets the action's tactic id.
     * @returns
     *  The action's tactic id.
     */
    private getTacticId(): string {
        const ttp = this.object.properties.get("ttp", TTPTupleProperty);
        const tactic = ttp?.get("tactic", StringProperty);
        if (!tactic?.value) {
            throw new Error("Action TTP mapping is missing a tactic value.");
        }
        return tactic.value;
    }

    /**
     * Sets the action name to the selected technique name.
     * @param technique
     *  The tuple's technique property.
     * @param techniqueId
     *  The technique id.
     */
    private setDefaultName(
        object: DiagramObjectView,
        technique: StringProperty,
        techniqueId: string
    ): void {
        const name = object.properties.get("name", StringProperty);
        if (!name || name.isDefined()) {
            return;
        }
        const text = technique.options?.value.get(techniqueId)?.toString() ?? techniqueId;
        name.setValue(getTechniqueNameFromLabel(text));
    }

}
