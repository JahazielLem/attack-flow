import { describe, expect, it } from "vitest";
import { SpawnDetection } from "./SpawnDetection";
import { ThemeLoader } from "@OpenChart/ThemeLoader";
import { DiagramObjectViewFactory, DiagramViewFile } from "@OpenChart/DiagramView";
import { StringProperty, MultiSelectProperty } from "@OpenChart/DiagramModel";
import { roundNearestMultiple } from "@OpenChart/Utilities";
import { AttackFlow, AttackFlowObjects, BaseObjects } from "@/assets/configuration/AttackFlowTemplates";
import { LightTheme } from "@/assets/configuration/AttackFlowThemes/LightTheme";
import { formatLogSourceEntry } from "@/assets/configuration/AttackFlowTemplates/logSourceUtils";

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

describe("SpawnDetection", () => {
    it("spawns a detection from a detection source id", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnDetection(file, "DET0516", 12, 13);

        expect(command.sourceId).toBe("DET0516");
        expect(command.objectType).toBe("detection");
        expect(command.object.id).toBe("detection");
        expect(command.object.properties.get("detection_id", StringProperty)?.value).toBe("DET0516");
        expect(command.object.properties.get("name", StringProperty)?.value)
            .toBe("Behavioral Detection of Command and Scripting Interpreter Abuse");
    });

    it("populates detection-level log source options from the catalog union, none selected", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnDetection(file, "DET0516", 0, 0);
        const logSources = command.object.properties.get("log_sources", MultiSelectProperty);

        expect(logSources).toBeDefined();
        expect(logSources!.options.value.size).toBe(6);
        expect(logSources!.values.size).toBe(0);
        expect([...logSources!.options.value.keys()].join("\n")).toContain("WinEventLog:Sysmon");
    });

    it("formats log source name and channel for the property editor", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnDetection(file, "DET0516", 0, 0);
        const logSources = command.object.properties.get("log_sources", MultiSelectProperty)!;
        const firstOption = [...logSources.options.value.keys()][0];

        expect(formatLogSourceEntry(firstOption)).toContain("name:");
        expect(formatLogSourceEntry(firstOption)).toMatch(/^name: .+/);
    });

    it("shows compact log source names on the canvas block when selected", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnDetection(file, "DET0516", 0, 0);
        const logSources = command.object.properties.get("log_sources", MultiSelectProperty)!;
        logSources.setSelections([...logSources.options.value.keys()]);
        const blockText = logSources.toString();

        expect(blockText).toContain("• WinEventLog:Sysmon");
        expect(blockText).not.toContain("name:");
        expect(blockText).not.toContain("channel:");
    });

    it("positions from the configured detection's top-left corner", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnDetection(file, "DET0516", 20, 30, true);

        const width = command.object.face.boundingBox.width;
        const height = command.object.face.boundingBox.height;

        expect(command.object.x).toBe(roundNearestMultiple(20 + width / 2, file.canvas.grid[0]));
        expect(command.object.y).toBe(roundNearestMultiple(30 + height / 2, file.canvas.grid[1]));
    });

    it("rejects unknown detection ids", async () => {
        const file = await createAttackFlowFile();
        expect(() => new SpawnDetection(file, "DET0000", 10, 10))
            .toThrow("Unknown detection id 'DET0000'.");
    });
});
