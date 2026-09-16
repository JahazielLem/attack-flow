import { describe, expect, it } from "vitest";
import AttackFlowPublisher from "./AttackFlowPublisher";
import { AttackFlow, AttackFlowObjects, BaseObjects, StixObjects, StixObservables } from "../AttackFlowTemplates";
import { Block, DiagramModelFile, DiagramObjectFactory, FloatProperty, StringProperty, TupleProperty } from "@OpenChart/DiagramModel";
import { StixToAttackFlowConverter } from "@/assets/scripts/StixToAttackFlow/StixToAttackFlow";
import type { StixBundle } from "@/assets/scripts/StixToAttackFlow/StixTypes";

describe("Fork compatibility after upstream synchronization", () => {
    const createFile = () => {
        const factory = new DiagramObjectFactory({
            id: "attack_flow_v2",
            canvas: AttackFlow,
            templates: [...AttackFlowObjects, ...BaseObjects, ...StixObjects, ...StixObservables]
        });
        return { factory, file: new DiagramModelFile(factory) };
    };

    it.each([
        ["TA0002", "T1059", "T1059.001"],
        ["ST0001", "REC-0001", "REC-0001.01"],
        ["SSH.TA0043", "SSH.T2001", "SSH.T2001.001"]
    ])("round-trips %s and its technique/subtechnique through STIX", (tactic, technique, subtechnique) => {
        const { factory, file } = createFile();
        const action = factory.createNewDiagramObject("action", Block);
        action.properties.get("name", StringProperty)!.setValue("PowerShell execution");
        action.properties.get("ttp", TupleProperty)!.setValue([
            ["tactic", tactic],
            ["technique", technique],
            ["subtechnique", subtechnique]
        ]);
        file.canvas.addObject(action);

        const bundle = JSON.parse(new AttackFlowPublisher().publish(file)) as StixBundle;
        const exported = bundle.objects.find(obj => obj.type === "attack-action");
        expect(exported).toMatchObject({
            tactic_id: tactic,
            technique_id: technique,
            subtechnique_id: subtechnique
        });

        // External Space Shield flows may use the unprefixed framework IDs.
        if (exported?.type === "attack-action" && tactic.startsWith("SSH.")) {
            exported.tactic_id = tactic.slice(4);
            exported.technique_id = technique.slice(4);
            exported.subtechnique_id = subtechnique.slice(4);
        }

        const imported = new DiagramModelFile(factory, new StixToAttackFlowConverter(factory).convert(bundle));
        const restored = [...imported.canvas.objects].find(obj => obj.id === "action")!;
        expect(restored.properties.get("ttp", TupleProperty)!.toJson()).toMatchObject({
            tactic,
            technique,
            subtechnique
        });
    });

    it.each([
        ["sigmf_capture", "x-sigmf-capture"],
        ["raw_iq_capture", "x-raw-iq-capture"]
    ])("round-trips %s with fractional RF values", (template, stixType) => {
        const { factory, file } = createFile();
        const action = factory.createNewDiagramObject("action", Block);
        file.canvas.addObject(action);
        const capture = factory.createNewDiagramObject(template, Block);
        capture.properties.get("name", StringProperty)!.setValue("Ground station capture");
        capture.properties.get("frequency_hz", FloatProperty)!.setValue(145800000.25);
        capture.properties.get("sample_rate_hz", FloatProperty)!.setValue(2400000.5);
        file.canvas.addObject(capture);

        const bundle = JSON.parse(new AttackFlowPublisher().publish(file)) as StixBundle;
        expect(bundle.objects.find(obj => obj.type === stixType)).toMatchObject({
            name: "Ground station capture",
            frequency_hz: 145800000.25,
            sample_rate_hz: 2400000.5
        });

        const imported = new DiagramModelFile(factory, new StixToAttackFlowConverter(factory).convert(bundle));
        const restored = [...imported.canvas.objects].find(obj => obj.id === template)!;
        expect(restored.properties.get("frequency_hz", FloatProperty)!.value).toBe(145800000.25);
        expect(restored.properties.get("sample_rate_hz", FloatProperty)!.value).toBe(2400000.5);
    });

    it("retains countermeasures alongside upstream defensive objects", () => {
        const { factory, file } = createFile();
        for (const template of ["action", "countermeasure", "mitigation", "detection"]) {
            const block = factory.createNewDiagramObject(template, Block);
            block.properties.get("name", StringProperty)!.setValue(template);
            file.canvas.addObject(block);
        }

        const bundle = JSON.parse(new AttackFlowPublisher().publish(file)) as StixBundle;
        expect(bundle.objects.map(obj => obj.type)).toEqual(expect.arrayContaining([
            "course-of-action", "x-mitigation", "x-detection"
        ]));

        const imported = new DiagramModelFile(factory, new StixToAttackFlowConverter(factory).convert(bundle));
        expect([...imported.canvas.objects].map(obj => obj.id)).toEqual(expect.arrayContaining([
            "countermeasure", "mitigation", "detection"
        ]));
    });
});
