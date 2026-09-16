import { DiagramObjectType } from "@OpenChart/DiagramModel";
import { DiagramViewEditor } from "@OpenChart/DiagramEditor";
import { DarkStyle, LightStyle, BlogStyle, ThemeLoader, StyleGenerator } from "@OpenChart/ThemeLoader";
import { Alignment, DiagramObjectViewFactory, DiagramViewFile, FaceType } from "@OpenChart/DiagramView";
import LocalStorageManager from "../LocalStorageManager.ts";

const themeIdsToStyles : { [key: string] : StyleGenerator } = {
    dark_theme: DarkStyle,
    light_theme: LightStyle,
    blog_theme: BlogStyle
};

const storedThemeId : string = LocalStorageManager.getThemeId();
let themeIdToUse = "dark_theme";
if (Object.prototype.hasOwnProperty.call(themeIdsToStyles, storedThemeId)) {
    themeIdToUse = storedThemeId;
}
const styleToUse = themeIdsToStyles[themeIdToUse];

/**
 * Phantom theme.
 */
const PhantomTheme = ThemeLoader.unsafeLoad({
    id: themeIdToUse,
    name: "Phantom Theme",
    grid: [5, 5],
    scale: 2,
    designs: {
        __phantom_canvas: {
            type: FaceType.DotGridCanvas,
            attributes: Alignment.Grid,
            style: styleToUse.Canvas()
        }
    }
});

/**
 * Phantom view factory.
 */
const PhantomFactory = new DiagramObjectViewFactory({
    id: "__phantom_schema",
    canvas: {
        name: "__phantom_canvas",
        type: DiagramObjectType.Canvas
    },
    templates: []
}, PhantomTheme);

/**
 * Phantom view file.
 */
const PhantomFile = new DiagramViewFile(PhantomFactory);

/**
 * Phantom view editor.
 */
export const PhantomEditor = new DiagramViewEditor(PhantomFile);
