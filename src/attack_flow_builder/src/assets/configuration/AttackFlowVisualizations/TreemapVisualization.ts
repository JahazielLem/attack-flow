import { defineAsyncComponent, markRaw } from "vue";
import { type VisualizationRegistration } from "@/assets/scripts/Application/Visualization";

export const TreemapVisualization: VisualizationRegistration = {
    id: "treemap",
    title: "Treemap",
    component: markRaw(defineAsyncComponent(
        () => import("@/components/Visualizations/TreemapVisualization.vue")
    )),
    exportName: "Treemap",
    getExportRoot: (root: HTMLElement) => root.querySelector("#treemap-vis")
};
