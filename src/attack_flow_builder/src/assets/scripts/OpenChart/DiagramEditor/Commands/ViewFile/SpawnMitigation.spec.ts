import { describe, expect, it } from "vitest";
import { SpawnMitigation } from "./SpawnMitigation";
import { ThemeLoader } from "@OpenChart/ThemeLoader";
import { DiagramObjectViewFactory, DiagramViewFile } from "@OpenChart/DiagramView";
import { StringProperty } from "@OpenChart/DiagramModel";
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

describe("SpawnMitigation", () => {
    it("spawns a mitigation from a mitigation source id", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnMitigation(file, "M1021", 12, 13);

        expect(command.sourceId).toBe("M1021");
        expect(command.objectType).toBe("mitigation");
        expect(command.object.id).toBe("mitigation");
        expect(command.object.properties.get("mitigation_id", StringProperty)?.value).toBe("M1021");
        expect(command.object.properties.get("name", StringProperty)?.value).toBe("Restrict Web-Based Content");
    });

    it("positions from the configured mitigation's top-left corner", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnMitigation(file, "M1021", 20, 30, true);

        const width = command.object.face.boundingBox.width;
        const height = command.object.face.boundingBox.height;

        expect(command.object.x).toBe(roundNearestMultiple(20 + width / 2, file.canvas.grid[0]));
        expect(command.object.y).toBe(roundNearestMultiple(30 + height / 2, file.canvas.grid[1]));
    });

    it("rejects unknown mitigation ids", async () => {
        const file = await createAttackFlowFile();
        expect(() => new SpawnMitigation(file, "M0000", 10, 10))
            .toThrow("Unknown mitigation id 'M0000'.");
    });
});
