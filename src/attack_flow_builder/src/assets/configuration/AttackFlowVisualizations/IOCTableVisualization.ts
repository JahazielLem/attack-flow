import { defineAsyncComponent, markRaw } from "vue";
import { type VisualizationRegistration } from "@/assets/scripts/Application/Visualization";

export const IOCTableVisualization: VisualizationRegistration = {
    id: "ioc_table",
    title: "IOC Table",
    component: markRaw(defineAsyncComponent(
        () => import("@/components/Visualizations/IOCTable.vue")
    )),
    getExportRoot: (root: HTMLElement) => root.querySelector("#ioc-table-vis")
};
