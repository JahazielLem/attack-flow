import { describe, expect, it } from "vitest";
import { SpawnObject } from "./SpawnObject";
import { ThemeLoader } from "@OpenChart/ThemeLoader";
import { DiagramObjectViewFactory, DiagramViewFile } from "@OpenChart/DiagramView";
import { roundNearestMultiple } from "@OpenChart/Utilities";
import { AttackFlow, AttackFlowObjects, BaseObjects } from "@/assets/configuration/AttackFlowTemplates";
import { LightTheme } from "@/assets/configuration/AttackFlowThemes/LightTheme";

async function createAttackFlowFile(): Promise<DiagramViewFile> {
    const theme = await ThemeLoader.load(LightTheme);
    const factory = new DiagramObjectViewFactory({
        id: "attack_flow_v2",
        canvas: AttackFlow,
        templates: [
            ...AttackFlowObjects,
            ...BaseObjects
        ]
    }, theme);
    return new DiagramViewFile(factory);
}

describe("SpawnObject", () => {
    it("spawns an object by template id", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnObject(file, "action", 12, 13);

        expect(command.object.id).toBe("action");
        expect(command.object.x).toBe(10);
        expect(command.object.y).toBe(15);
        expect(file.canvas.blocks).not.toContain(command.object);

        command.execute();
        expect(file.canvas.blocks).toContain(command.object);

        command.undo();
        expect(file.canvas.blocks).not.toContain(command.object);
    });

    it("can position from the object's top-left corner", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnObject(file, "action", 20, 30, true);

        const width = command.object.face.boundingBox.width;
        const height = command.object.face.boundingBox.height;

        expect(command.object.x).toBe(roundNearestMultiple(20 + width / 2, file.canvas.grid[0]));
        expect(command.object.y).toBe(roundNearestMultiple(30 + height / 2, file.canvas.grid[1]));
    });
});
