import { describe, expect, it } from "vitest";
import { SpawnDetection } from "@/assets/scripts/OpenChart/DiagramEditor/Commands/ViewFile/SpawnDetection";
import { SpawnObject } from "@/assets/scripts/OpenChart/DiagramEditor/Commands/ViewFile/SpawnObject";
import { ThemeLoader } from "@OpenChart/ThemeLoader";
import { DiagramObjectViewFactory, DiagramViewFile } from "@OpenChart/DiagramView";
import { AttackFlow, AttackFlowObjects, BaseObjects } from "@/assets/configuration/AttackFlowTemplates";
import { LightTheme } from "@/assets/configuration/AttackFlowThemes/LightTheme";
import {
    hasVisibleEditorProperties,
    isVisibleEditorProperty
} from "./editorPropertyUtils";

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

describe("editorPropertyUtils", () => {
    it("reports visible editor properties on spawned detections", async () => {
        const file = await createAttackFlowFile();
        const command = new SpawnDetection(file, "DET0516", 0, 0);
        const visibility = [...command.object.properties.value.entries()].map(([key, property]) => ({
            key,
            visible: isVisibleEditorProperty(property)
        }));

        expect(visibility).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ key: "name", visible: true }),
                expect.objectContaining({ key: "detection_id", visible: true }),
                expect.objectContaining({ key: "log_sources", visible: true })
            ])
        );
        expect(visibility.some(entry => entry.key === "analytics")).toBe(false);
        expect(hasVisibleEditorProperties(command.object.properties)).toBe(true);
    });

    it("blank detection exposes editable sidebar fields", async () => {
        const file = await createAttackFlowFile();
        const detection = new SpawnObject(file, "detection", 0, 0).object;
        expect(hasVisibleEditorProperties(detection.properties)).toBe(true);
    });
});
