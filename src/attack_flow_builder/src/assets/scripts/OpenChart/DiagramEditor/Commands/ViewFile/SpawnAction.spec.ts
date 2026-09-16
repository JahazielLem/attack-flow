import { describe, expect, it } from "vitest";
import { SpawnAction } from "./SpawnAction";
import { ThemeLoader } from "@OpenChart/ThemeLoader";
import { DiagramObjectViewFactory, DiagramViewFile } from "@OpenChart/DiagramView";
import { StringProperty, TTPTupleProperty } from "@OpenChart/DiagramModel";
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

describe("SpawnAction", () => {
    it("spawns an action with technique and tactic ids", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnAction(file, "T1059", 10, 10);

        const ttp = command.object.properties.get("ttp", TTPTupleProperty)!;
        const technique = ttp.get("technique", StringProperty)!;
        const tactic = ttp.get("tactic", StringProperty)!;
        const name = command.object.properties.get("name", StringProperty)!;

        expect(command.techniqueId).toBe("T1059");
        expect(command.tacticId).toBe("TA0002");
        expect(technique.value).toBe("T1059");
        expect(tactic.value).toBe("TA0002");
        expect(name.value).toBe("Command and Scripting Interpreter");

        command.execute();
        expect(file.canvas.blocks).toContain(command.object);
    });

    it("spawns an ATLAS action with technique and tactic ids", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnAction(file, "AML.T0000", 10, 10);

        const ttp = command.object.properties.get("ttp", TTPTupleProperty)!;
        const technique = ttp.get("technique", StringProperty)!;
        const tactic = ttp.get("tactic", StringProperty)!;
        const name = command.object.properties.get("name", StringProperty)!;

        expect(command.techniqueId).toBe("AML.T0000");
        expect(command.tacticId).toBe("AML.TA0002");
        expect(technique.value).toBe("AML.T0000");
        expect(tactic.value).toBe("AML.TA0002");
        expect(name.value).toBe("Search Open Technical Databases");
    });

    it("positions from the configured action's top-left corner", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnAction(file, "T1059", 20, 30, true);

        const width = command.object.face.boundingBox.width;
        const height = command.object.face.boundingBox.height;

        expect(command.object.x).toBe(roundNearestMultiple(20 + width / 2, file.canvas.grid[0]));
        expect(command.object.y).toBe(roundNearestMultiple(30 + height / 2, file.canvas.grid[1]));
    });

    it("rejects unknown technique ids", async () => {
        const file = await createAttackFlowFile();
        expect(() => new SpawnAction(file, "T0000", 10, 10)).toThrow("Unknown technique id 'T0000'.");
    });
});
