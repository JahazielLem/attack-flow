import { BlockView, LineView, type LatchView } from "../../../DiagramView";
import { GroupCommand } from "../GroupCommand";
import { AttachLatchToAnchor, MoveObjectsTo } from "../index.commands";
import type { SpawnObject } from "./SpawnObject";

const line_directions_to_target_anchors = {
    n: "270",
    s: "90",
    e: "180",
    w: "0"
};

/**
 * A command that spawns an object and attaches it to a latch.
 */
export class SpawnObjectConnectedToLatch extends GroupCommand {
    constructor(spawnCommand: SpawnObject, latch: LatchView) {
        super();

        this.do(spawnCommand);

        if (!latch.parent) { return; }

        const line : LineView = latch.parent as LineView;

        const line_dir = line.getPointingDirection();

        if (!line_dir) { return; }

        if (spawnCommand.object instanceof BlockView) {
            const anchors = spawnCommand.object.anchors;
            const anchor_key = line_directions_to_target_anchors[line_dir];
            const anchor = anchors.get(anchor_key);

            if (!anchor) { return; }

            const moveLatchCommand = new MoveObjectsTo(latch, anchor.x, anchor.y);
            const attachCommand = new AttachLatchToAnchor(latch, anchor);
            this.do(moveLatchCommand);
            this.do(attachCommand);
        }
    }
}
