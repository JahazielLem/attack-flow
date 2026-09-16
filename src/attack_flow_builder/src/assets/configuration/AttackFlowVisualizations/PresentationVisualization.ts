import { defineAsyncComponent, markRaw } from "vue";
import { type VisualizationRegistration } from "@/assets/scripts/Application/Visualization";

export const PresentationVisualization: VisualizationRegistration = {
    id: "presentation",
    title: "Presentation",
    component: markRaw(defineAsyncComponent(
        () => import("@/components/Visualizations/PresentationVis.vue")
    )),
    getExportRoot: (root: HTMLElement) => root.querySelector(".diagram-shell")
};
