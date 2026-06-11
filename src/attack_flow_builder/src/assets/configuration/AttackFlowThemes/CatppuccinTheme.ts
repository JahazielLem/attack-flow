import { DarkStyle } from "@OpenChart/ThemeLoader";
import { Alignment, FaceType, Orientation } from "@OpenChart/DiagramView";
import { StixObjects, StixObservables } from "../AttackFlowTemplates";
import type { DiagramThemeConfiguration } from "@OpenChart/ThemeLoader";

const Colors = {
    red: { fill_color: "#b84b6d", stroke_color: "#f38ba8" },
    blue: { fill_color: "#4c6ea8", stroke_color: "#89b4fa" },
    orange: { fill_color: "#b87845", stroke_color: "#fab387" },
    green: { fill_color: "#4f8f66", stroke_color: "#a6e3a1" },
    gray: { fill_color: "#45475a", stroke_color: "#585b70" }
};

const BaseObjects = {
    dynamic_line: {
        type: FaceType.DynamicLine,
        attributes: Alignment.Grid,
        style: DarkStyle.Line()
    },
    vertical_anchor: {
        type: FaceType.AnchorPoint,
        attributes: Orientation.D90,
        style: {
            radius: 10,
            fill_color: "rgba(255, 255, 255, 0.25)",
            stroke_color: "rgba(255, 255, 255, 0.25)",
            stroke_width: 0
        }
    },
    horizontal_anchor: {
        type: FaceType.AnchorPoint,
        attributes: Orientation.D0,
        style: {
            radius: 10,
            fill_color: "rgba(255, 255, 255, 0.25)",
            stroke_color: "rgba(255, 255, 255, 0.25)",
            stroke_width: 0
        }
    },
    generic_latch: {
        type: FaceType.LatchPoint,
        attributes: Alignment.Grid,
        style: {
            radius: 8,
            fill_color: "rgba(243, 139, 168, 0.35)",
            stroke_color: "#141414",
            stroke_width: 0
        }
    },
    generic_handle: {
        type: FaceType.HandlePoint,
        attributes: Alignment.Grid,
        style: DarkStyle.Point()
    }
};

const AttackObjects = {
    flow: {
        type: FaceType.DotGridCanvas,
        style: DarkStyle.Canvas()
    },
    action: {
        type: FaceType.DictionaryBlock,
        attributes: Alignment.Grid,
        style: DarkStyle.DictionaryBlock({ head: Colors.red })
    },
    asset: {
        type: FaceType.DictionaryBlock,
        attributes: Alignment.Grid,
        style: DarkStyle.DictionaryBlock({ head: Colors.orange })
    },
    countermeasure: {
        type: FaceType.DictionaryBlock,
        attributes: Alignment.Grid,
        style: DarkStyle.DictionaryBlock({ head: Colors.blue })
    },
    condition: {
        type: FaceType.BranchBlock,
        attributes: Alignment.Grid,
        style: DarkStyle.BranchBlock({ head: Colors.green })
    },
    OR_operator: {
        type: FaceType.TextBlock,
        attributes: Alignment.Grid,
        style: DarkStyle.TextBlock(Colors.red)
    },
    AND_operator: {
        type: FaceType.TextBlock,
        attributes: Alignment.Grid,
        style: DarkStyle.TextBlock(Colors.red)
    }
};

const Stix = new Map<string, DiagramThemeConfiguration["designs"][number]>();
for (const object of [...StixObjects, ...StixObservables]) {
    Stix.set(object.name, {
        type: FaceType.DictionaryBlock,
        attributes: Alignment.Grid,
        style: DarkStyle.DictionaryBlock({ head: Colors.gray })
    });
}

export const CatppuccinTheme: DiagramThemeConfiguration = {
    id: "catppuccin_theme",
    name: "Catppuccin Theme",
    grid: [5, 5],
    scale: 2,
    designs: Object.fromEntries([
        ...Object.entries(BaseObjects),
        ...Object.entries(AttackObjects),
        ...Stix.entries()
    ])
};
