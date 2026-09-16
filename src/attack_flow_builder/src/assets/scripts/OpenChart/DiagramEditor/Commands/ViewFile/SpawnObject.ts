import { GroupCommand } from "../GroupCommand";
import { addObjectToGroup } from "../Model";
import { Alignment, DiagramViewFile } from "@OpenChart/DiagramView";
import { round, roundNearestMultiple } from "@OpenChart/Utilities";
import type { DiagramObjectView } from "@OpenChart/DiagramView";

export class SpawnObject extends GroupCommand {

    /**
     * The spawned object.
     */
    public readonly object: DiagramObjectView;


    /**
     * Spawns an object in a diagram file.
     * @param file
     *  The diagram file.
     * @param id
     *  The object's id.
     * @param x
     *  The object's x-coordinate.
     * @param y
     *  The object's y-coordinate.
     * @param fromCorner
     *  Whether to position the object from its top-left corner or its center.
     *  (Default: `false`)
     */
    constructor(file: DiagramViewFile, id: string, x: number, y: number, fromCorner: boolean = false) {
        super();
        // Create object
        this.object = this.createObject(file, id);
        // Configure object
        this.configureObject(this.object, id);
        // Calculate object size
        this.object.calculateLayout();
        // Position object
        this.positionObject(file, x, y, fromCorner);
        // Add object to group
        this.do(addObjectToGroup(this.object, file.canvas));
    }

    /**
     * Positions the object.
     * @param file
     *  The diagram file.
     * @param x
     *  The object's x-coordinate.
     * @param y
     *  The object's y-coordinate.
     * @param fromCorner
     *  Whether to position the object from its top-left corner or its center.
     */
    protected positionObject(file: DiagramViewFile, x: number, y: number, fromCorner: boolean = false): void {
        if (fromCorner) {
            x += this.object.face.boundingBox.width / 2;
            y += this.object.face.boundingBox.height / 2;
        }
        // Align coordinates
        if (this.object.alignment === Alignment.Grid) {
            x = roundNearestMultiple(x, file.canvas.grid[0]);
            y = roundNearestMultiple(y, file.canvas.grid[1]);
        } else {
            x = round(x);
            y = round(y);
        }
        // Position object
        this.object.moveTo(x, y);
    }

    /**
     * Creates the object to spawn.
     * @param file
     *  The diagram file.
     * @param id
     *  The object's id.
     * @returns
     *  The object to spawn.
     */
    protected createObject(file: DiagramViewFile, id: string): DiagramObjectView {
        return file.factory.createNewDiagramObject(id);
    }

    /**
     * Configures the object before layout and placement.
     * @param object
     *  The object to spawn.
     * @param id
     *  The object's id.
     */
    protected configureObject(_object: DiagramObjectView, _id: string): void {}

}
