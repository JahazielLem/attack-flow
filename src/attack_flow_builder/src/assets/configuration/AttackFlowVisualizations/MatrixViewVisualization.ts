import { defineAsyncComponent, markRaw } from "vue";
import { type VisualizationRegistration } from "@/assets/scripts/Application/Visualization";

export const MatrixViewVisualization: VisualizationRegistration = {
    id: "matrix_view",
    title: "Matrix View",
    component: markRaw(defineAsyncComponent(
        () => import("@/components/Visualizations/MatrixView.vue")
    )),
    getExportRoot: (root: HTMLElement) => root.querySelector(".svg-container")
};
