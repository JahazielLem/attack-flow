import {
    createSvgClassificationMarking,
    drawClassificationMarking,
    formatClassificationText,
    getClassificationTextColor
} from "@/assets/scripts/Application/Classification";
import { Device } from "@/assets/scripts/Browser";
import {
    EnumProperty,
    StringProperty,
    TupleProperty
} from "@/assets/scripts/OpenChart/DiagramModel";
import { toCanvas, toSvg } from "html-to-image";
import type { Options } from "html-to-image/lib/types";
import type { Component } from "vue";
import type { ApplicationStore } from "@/stores/ApplicationStore";

export interface VisualizationRegistration {

    /**
     * The visualization's unique identifier.
     */
    id: string;

    /**
     * The visualization's display title.
     */
    title: string;

    /**
     * The visualization's Vue component.
     */
    component: Component;

    /**
     * A custom name for the exported file.
     */
    exportName?: string | ((app: ApplicationStore) => string);

    /**
     * A custom root for exports.
     */
    getExportRoot?: (root: HTMLElement) => HTMLElement | null;

    /**
     * A custom exporter for the visualization.
     */
    exporter?: VisualizationExporter;

}

export interface VisualizationModalController {

    /**
     * The available visualizations.
     */
    readonly visualizations: readonly VisualizationRegistration[];

    /**
     * Whether the modal is open.
     */
    active: boolean;

    /**
     * The active visualization.
     */
    readonly activeVisualization?: VisualizationRegistration;

    /**
     * Opens a visualization in the modal.
     * @param id
     *  The visualization's identifier.
     */
    open(id: string): void;

    /**
     * Closes the modal.
     */
    close(): void;

}

export interface VisualizationExportContext {

    /**
     * The application store.
     */
    app: ApplicationStore;

    /**
     * The visualization being exported.
     */
    visualization: VisualizationRegistration;

    /**
     * The visualization's rendered root element.
     */
    root: HTMLElement;

}

export type VisualizationExporter = (
    context: VisualizationExportContext
) => Promise<void>;

/**
 * Exports a visualization with either its custom exporter or the default SVG
 * exporter.
 *
 * This path prefers higher-fidelity export output, with SVG used by default
 * when available. Unlike {@link copyVisualizationToClipboard}, which
 * optimizes for clipboard compatibility, export/download favors a more
 * complete representation of the visualization.
 * @param context
 *  The visualization export context.
 */
export async function exportVisualization(
    context: VisualizationExportContext
): Promise<void> {
    const { visualization } = context;
    if (visualization.exporter) {
        await visualization.exporter(context);
    } else {
        await liteSvgExporter(context);
    }
}

/**
 * Maximum width for clipboard images so pastes work reliably in Teams and
 * PowerPoint without exceeding typical clipboard size limits.
 */
const MAX_CLIPBOARD_IMAGE_WIDTH = 1200;

/** XML namespace used when creating SVG export nodes. */
const SVG_NS = "http://www.w3.org/2000/svg";

/** Font size for exported classification marking text. */
const CLASSIFICATION_FONT_SIZE = 16;

/** Horizontal padding inside the classification marking banner. */
const CLASSIFICATION_PADDING_X = 5;

/** Vertical padding inside the classification marking banner. */
const CLASSIFICATION_PADDING_Y = 2;

/** Estimated width multiplier used to size the classification banner. */
const CLASSIFICATION_TEXT_WIDTH_FACTOR = 0.62;

/** Gap between the classification banner and the exported visualization. */
const CLASSIFICATION_CONTENT_GAP = 4;

/**
 * Applied to visualization toolbars and controls that should be excluded from
 * clipboard captures. New visualizations should add this class to any UI
 * chrome that should not appear in copied images.
 */
const VISUALIZATION_EXPORT_IGNORE_CLASS = "visualization-export-ignore";

/**
 * Resolves the element to capture for clipboard copy.
 */
function getClipboardExportRoot(context: VisualizationExportContext): Element {
    const exportRoot = context.visualization.getExportRoot?.(context.root);
    return exportRoot instanceof Element ? exportRoot : context.root;
}

/**
 * Resolves the element to capture for visualization export.
 */
function getVisualizationExportRoot(context: VisualizationExportContext): Element {
    return context.visualization.getExportRoot?.(context.root)
        ?? context.root;
}

/** Classification marking text and styling derived from the active file. */
interface ClassificationMarkingData {
    /** Fully formatted marking text to display in the export banner. */
    fullText: string;

    /** Text color used for the formatted marking text. */
    textColor: string;
}

/** Resolved SVG viewport dimensions used for export layout. */
interface SvgViewport {
    /** Left edge of the SVG viewport. */
    x: number;

    /** Top edge of the SVG viewport. */
    y: number;

    /** Width of the SVG viewport. */
    width: number;

    /** Height of the SVG viewport. */
    height: number;
}

/** SVG viewport dimensions after top padding has been reserved. */
interface PaddedSvgViewport {
    /** Left edge of the padded SVG viewport. */
    x: number;

    /** Top edge of the padded SVG viewport. */
    y: number;

    /** Width of the padded SVG viewport. */
    width: number;

    /** Height of the padded SVG viewport. */
    height: number;

    /** Vertical offset applied to the original SVG content. */
    contentOffsetY: number;
}

/**
 * Decorates an SVG export with the active file's classification marking.
 * Returns the provided SVG so exporters can compose the helper inline.
 * @param svg
 *  The SVG to decorate.
 * @param app
 *  The application store containing the active file classification.
 * @returns
 *  The decorated SVG.
 */
export function addClassificationMarking(
    svg: SVGSVGElement,
    app: ApplicationStore
): SVGSVGElement {
    // Resolve the formatted marking text and exit early when none is set.
    const markingData = getClassificationMarkingData(app);
    if (!markingData) {
        return svg;
    }

    svg.querySelector("[data-classification-marking='true']")?.remove();

    // Reserve space for the banner before positioning the new SVG elements.
    const estimatedTextWidth = Math.ceil(
        markingData.fullText.length
        * CLASSIFICATION_FONT_SIZE
        * CLASSIFICATION_TEXT_WIDTH_FACTOR
    );
    const rectWidth = estimatedTextWidth + (CLASSIFICATION_PADDING_X * 2);
    const rectHeight = CLASSIFICATION_FONT_SIZE + (CLASSIFICATION_PADDING_Y * 2);
    const topPadding = rectHeight + CLASSIFICATION_CONTENT_GAP;
    const paddedViewport = ensureSvgTopPadding(svg, topPadding);
    const rectX = paddedViewport.x + ((paddedViewport.width - rectWidth) / 2);
    const rectY = paddedViewport.y;

    // Append the completed banner as the last SVG layer in the export.
    svg.append(createSvgClassificationMarking(svg, markingData.fullText, {
        textColor: markingData.textColor,
        x: rectX,
        y: rectY
    }));
    return svg;
}

/**
 * Resolves a single SVG element from an export root when present.
 */
function resolveExportSvg(exportRoot: Element): SVGSVGElement | null {
    if (exportRoot instanceof SVGSVGElement) {
        return exportRoot;
    }

    const svg = exportRoot.querySelector("svg");
    return svg instanceof SVGSVGElement ? svg : null;
}

/** Resolves formatted classification marking data from the active file. */
function getClassificationMarkingData(
    app: ApplicationStore
): ClassificationMarkingData | null {
    const classification = app.activeEditor.file.canvas.properties
        .get<TupleProperty>("classification");
    const marking = classification?.get<EnumProperty>("marking");
    const group = classification?.get<StringProperty>("group");
    if (!marking?.value) {
        return null;
    }

    const markingText = marking.toString();
    const groupText = group?.value ?? null;
    return {
        fullText: formatClassificationText(markingText, groupText),
        textColor: getClassificationTextColor(markingText)
    };
}

/** Resolves the SVG viewport origin and dimensions used for banner layout. */
function getSvgViewport(svg: SVGSVGElement): SvgViewport {
    const viewBox = svg.getAttribute("viewBox");
    if (viewBox) {
        const [x, y, width, height] = viewBox.split(/[\s,]+/).map(Number);
        if ([x, y, width, height].every(Number.isFinite)) {
            return { x, y, width, height };
        }
    }

    const { width, height } = resolveSvgDimensions(svg);
    return {
        x: 0,
        y: 0,
        width,
        height
    };
}

/** Expands the SVG to reserve top padding for the classification banner. */
function ensureSvgTopPadding(svg: SVGSVGElement, topPadding: number): PaddedSvgViewport {
    const paddingKey = "data-classification-padding-top";
    const existingPadding = Number(svg.getAttribute(paddingKey) ?? "0");
    if (existingPadding > 0) {
        const viewport = getSvgViewport(svg);
        return {
            ...viewport,
            contentOffsetY: existingPadding
        };
    }

    const viewport = getSvgViewport(svg);
    wrapSvgContent(svg, topPadding);
    const paddedViewport = {
        x: viewport.x,
        y: viewport.y,
        width: viewport.width,
        height: viewport.height + topPadding,
        contentOffsetY: topPadding
    };
    svg.setAttribute(
        "viewBox",
        `${paddedViewport.x} ${paddedViewport.y} ${paddedViewport.width} ${paddedViewport.height}`
    );
    updateSvgLengthAttribute(svg, "height", topPadding);
    svg.setAttribute(paddingKey, String(topPadding));
    return paddedViewport;
}

/** Wraps existing SVG content so it can be shifted below the banner area. */
function wrapSvgContent(svg: SVGSVGElement, topPadding: number): void {
    const contentGroupKey = "data-classification-content";
    const existingGroup = svg.querySelector(`:scope > g[${contentGroupKey}='true']`);
    if (existingGroup?.tagName?.toLowerCase() === "g") {
        return;
    }

    const documentRoot = svg.ownerDocument ?? document;
    const contentGroup = documentRoot.createElementNS(SVG_NS, "g");
    contentGroup.setAttribute(contentGroupKey, "true");
    contentGroup.setAttribute("transform", `translate(0 ${topPadding})`);

    const nodesToMove = Array.from(svg.childNodes).filter(node => {
        if (!(node instanceof Element)) {
            return false;
        }

        const tagName = node.tagName.toLowerCase();
        return ![
            "defs",
            "title",
            "desc",
            "metadata",
            "style",
            "script"
        ].includes(tagName)
            && node.getAttribute("data-classification-marking") !== "true";
    });

    if (!nodesToMove.length) {
        return;
    }

    for (const node of nodesToMove) {
        contentGroup.append(node);
    }

    svg.append(contentGroup);
}

/** Adjusts a numeric SVG length attribute by the provided delta. */
function updateSvgLengthAttribute(
    svg: SVGSVGElement,
    attribute: "height" | "width",
    delta: number
): void {
    const rawValue = svg.getAttribute(attribute);
    if (!rawValue) {
        return;
    }

    const match = rawValue.trim().match(/^([+-]?\d*\.?\d+)([a-z%]*)$/i);
    if (!match) {
        return;
    }

    const [, valueText, unit] = match;
    const value = Number(valueText);
    if (!Number.isFinite(value)) {
        return;
    }

    svg.setAttribute(attribute, `${value + delta}${unit}`);
}

/**
 * Excludes visualization UI chrome marked with
 * {@link VISUALIZATION_EXPORT_IGNORE_CLASS} from clipboard captures.
 */
function shouldIncludeClipboardCaptureNode(node: Node): boolean {
    return !(node instanceof Element)
        || !node.closest(`.${VISUALIZATION_EXPORT_IGNORE_CLASS}`);
}

/**
 * Returns html-to-image options for clipboard capture.
 */
function buildClipboardCaptureOptions(
    dimensions: { width: number, height: number }
): Options {
    return {
        cacheBust: true,
        filter: shouldIncludeClipboardCaptureNode,
        width: dimensions.width,
        height: dimensions.height,
        backgroundColor: "rgba(0,0,0,0)",
        pixelRatio: 1,
        style: {
            overflow: "hidden",
            scrollbarWidth: "none",
            background: "transparent",
            backgroundColor: "transparent"
        }
    };
}

/**
 * Resolves the intrinsic size of an SVG element for clipboard rasterization.
 */
function resolveSvgDimensions(svg: SVGSVGElement): { width: number, height: number } {
    const widthMatch = svg.getAttribute("width")?.trim().match(/^([+-]?\d*\.?\d+)([%a-z]*)$/i);
    const heightMatch = svg.getAttribute("height")?.trim().match(/^([+-]?\d*\.?\d+)([%a-z]*)$/i);
    if (widthMatch && heightMatch && widthMatch[2] !== "%" && heightMatch[2] !== "%") {
        const width = Number(widthMatch[1]);
        const height = Number(heightMatch[1]);
        if (width > 0 && height > 0) {
            return { width, height };
        }
    }

    const viewBox = svg.getAttribute("viewBox");
    if (viewBox) {
        const [, , width, height] = viewBox.split(/[\s,]+/).map(Number);
        if (Number.isFinite(width) && Number.isFinite(height) && width > 0 && height > 0) {
            return { width, height };
        }
    }

    try {
        const bbox = svg.getBBox();
        const bboxWidth = Math.ceil(bbox.width);
        const bboxHeight = Math.ceil(bbox.height);
        if (bboxWidth > 0 && bboxHeight > 0) {
            return { width: bboxWidth, height: bboxHeight };
        }
    } catch {
        // getBBox throws when the SVG is not rendered.
    }

    throw new Error("Unable to determine visualization size.");
}

/**
 * Resolves the intrinsic clipboard capture dimensions for an HTML export
 * root before any clipboard downscaling is applied.
 */
function getClipboardImageDimensions(element: HTMLElement): { width: number, height: number } {
    const width = element.scrollWidth || element.clientWidth;
    const height = element.scrollHeight || element.clientHeight;

    if (!width || !height) {
        throw new Error("Unable to determine visualization size.");
    }

    return { width, height };
}

/**
 * Scales visualization dimensions down for clipboard pasting while preserving
 * aspect ratio.
 */
function scaleDimensionsForClipboard(
    sourceWidth: number,
    sourceHeight: number
): { width: number, height: number } {
    if (sourceWidth <= MAX_CLIPBOARD_IMAGE_WIDTH) {
        return { width: sourceWidth, height: sourceHeight };
    }

    const scale = MAX_CLIPBOARD_IMAGE_WIDTH / sourceWidth;
    return {
        width: Math.round(sourceWidth * scale),
        height: Math.round(sourceHeight * scale)
    };
}

/**
 * Clones an SVG for clipboard raster export without scroll-container layout
 * constraints.
 */
function prepareSvgForRasterExport(
    svg: SVGSVGElement,
    width: number,
    height: number
): SVGSVGElement {
    const clone = svg.cloneNode(true) as SVGSVGElement;
    const sourceViewBox = svg.getAttribute("viewBox");

    if (sourceViewBox) {
        clone.setAttribute("viewBox", sourceViewBox);
    } else {
        try {
            const bbox = svg.getBBox();
            clone.setAttribute(
                "viewBox",
                `${bbox.x} ${bbox.y} ${bbox.width} ${bbox.height}`
            );
        } catch {
            // getBBox throws when the SVG is not rendered.
        }
    }

    clone.setAttribute("width", String(width));
    clone.setAttribute("height", String(height));
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    clone.style.minWidth = "auto";
    clone.style.minHeight = "auto";
    clone.style.width = `${width}px`;
    clone.style.height = `${height}px`;
    clone.style.overflow = "visible";
    clone.style.maxWidth = "none";
    clone.style.maxHeight = "none";
    return clone;
}

/** Returns the extra top space reserved for raster clipboard markings. */
function getClipboardClassificationOffset(): number {
    return CLASSIFICATION_FONT_SIZE
        + (CLASSIFICATION_PADDING_Y * 2)
        + CLASSIFICATION_CONTENT_GAP;
}

/**
 * Adds the classification marking to a raster clipboard canvas when present.
 */
function decorateCanvasForClipboardExport(
    canvas: HTMLCanvasElement,
    app: ApplicationStore
): HTMLCanvasElement {
    const markingData = getClassificationMarkingData(app);
    if (!markingData) {
        return canvas;
    }

    const classificationOffset = getClipboardClassificationOffset();
    const outputCanvas = document.createElement("canvas");
    outputCanvas.width = canvas.width;
    outputCanvas.height = canvas.height + classificationOffset;
    const context = outputCanvas.getContext("2d");
    if (!context) {
        throw new Error("Unable to render visualization image.");
    }

    context.clearRect(0, 0, outputCanvas.width, outputCanvas.height);
    context.drawImage(canvas, 0, classificationOffset);
    context.font = `600 ${CLASSIFICATION_FONT_SIZE}px sans-serif`;
    drawClassificationMarking(context, markingData.fullText, {
        textColor: markingData.textColor
    });
    return outputCanvas;
}

/**
 * Rasterizes an SVG element to a transparent PNG blob at clipboard-friendly
 * dimensions. Uses native SVG serialization so the full graphic is captured
 * instead of the visible scroll viewport.
 */
async function rasterizeSvgElementToPngBlob(
    svg: SVGSVGElement,
    app: ApplicationStore
): Promise<Blob> {
    const sourceDimensions = resolveSvgDimensions(svg);
    const outputDimensions = scaleDimensionsForClipboard(
        sourceDimensions.width,
        sourceDimensions.height
    );
    const exportSvg = prepareSvgForRasterExport(
        svg,
        sourceDimensions.width,
        sourceDimensions.height
    );
    const svgText = new XMLSerializer().serializeToString(exportSvg);
    const svgUrl = URL.createObjectURL(
        new Blob([svgText], { type: "image/svg+xml;charset=utf-8" })
    );

    try {
        const image = await loadImage(svgUrl);
        const canvas = document.createElement("canvas");
        canvas.width = outputDimensions.width;
        canvas.height = outputDimensions.height;
        const context = canvas.getContext("2d");
        if (!context) {
            throw new Error("Unable to render visualization image.");
        }
        context.clearRect(0, 0, canvas.width, canvas.height);
        context.drawImage(
            image,
            0,
            0,
            outputDimensions.width,
            outputDimensions.height
        );
        return await canvasToPngBlob(
            decorateCanvasForClipboardExport(canvas, app)
        );
    } finally {
        URL.revokeObjectURL(svgUrl);
    }
}

/** Loads an image element from a blob or data URL. */
function loadImage(url: string): Promise<HTMLImageElement> {
    return new Promise((resolve, reject) => {
        const image = new Image();
        image.onload = () => resolve(image);
        image.onerror = () => reject(new Error("Unable to render visualization image."));
        image.src = url;
    });
}

/** Converts a canvas into a PNG blob for clipboard export. */
function canvasToPngBlob(canvas: HTMLCanvasElement): Promise<Blob> {
    return new Promise((resolve, reject) => {
        canvas.toBlob(
            blob => blob ? resolve(blob) : reject(new Error("Unable to render visualization image.")),
            "image/png"
        );
    });
}

/**
 * Rasterizes an HTML export root to a clipboard-friendly PNG blob.
 */
async function rasterizeHtmlElementToPngBlob(
    element: HTMLElement,
    app: ApplicationStore
): Promise<Blob> {
    const sourceDimensions = getClipboardImageDimensions(element);
    const outputDimensions = scaleDimensionsForClipboard(
        sourceDimensions.width,
        sourceDimensions.height
    );
    const captureOptions = buildClipboardCaptureOptions(sourceDimensions);
    const canvas = await toCanvas(element, {
        ...captureOptions,
        width: sourceDimensions.width,
        height: sourceDimensions.height,
        canvasWidth: outputDimensions.width,
        canvasHeight: outputDimensions.height,
        style: {
            ...captureOptions.style,
            width: `${sourceDimensions.width}px`,
            height: `${sourceDimensions.height}px`
        }
    });
    return await canvasToPngBlob(
        decorateCanvasForClipboardExport(canvas, app)
    );
}

/**
 * Resolves a decorated SVG representation for visualization export or copy.
 */
async function resolveVisualizationExportSvg(
    context: VisualizationExportContext
): Promise<SVGSVGElement> {
    const exportRoot = getVisualizationExportRoot(context);
    const svg = resolveExportSvg(exportRoot);
    if (svg) {
        return addClassificationMarking(
            svg.cloneNode(true) as SVGSVGElement,
            context.app
        );
    }

    if (!(exportRoot instanceof HTMLElement)) {
        throw new Error("Unable to render visualization image.");
    }

    const svgDataUrl = await toSvg(exportRoot, {
        cacheBust: true,
        filter: shouldIncludeClipboardCaptureNode
    });
    const svgText = svgDataUrlToText(svgDataUrl);
    const documentRoot = new DOMParser().parseFromString(svgText, "image/svg+xml");
    const generatedSvg = documentRoot.documentElement;
    if (generatedSvg.tagName.toLowerCase() !== "svg") {
        throw new Error("Unable to render visualization image.");
    }

    return addClassificationMarking(
        generatedSvg as unknown as SVGSVGElement,
        context.app
    );
}

/**
 * Copies a visualization to the device's clipboard as a transparent PNG image.
 *
 * This path prioritizes compatibility and convenience for quick paste
 * workflows. Unlike {@link exportVisualization}, which prefers SVG output
 * for fidelity, clipboard copy uses a scaled PNG because Teams, PowerPoint,
 * and similar apps tend to handle pasted `image/png` content more reliably
 * than large SVG clipboard payloads.
 * @param context
 *  The visualization export context.
 */
export async function copyVisualizationToClipboard(
    context: VisualizationExportContext
): Promise<void> {
    const exportRoot = getClipboardExportRoot(context);
    const svg = resolveExportSvg(exportRoot);
    const pngBlob = svg
        ? await rasterizeSvgElementToPngBlob(svg, context.app)
        : exportRoot instanceof HTMLElement
            ? await rasterizeHtmlElementToPngBlob(exportRoot, context.app)
            : (() => {
                throw new Error("Unable to render visualization image.");
            })();
    try {
        await navigator.clipboard.write([
            new ClipboardItem({ "image/png": pngBlob })
        ]);
    } catch {
        alert(
            "Clipboard access has been prohibited. " +
            "Please grant the required clipboard permissions."
        );
    }
}

/**
 * Exports a visualization as an SVG file using html-to-image.
 * @param context
 *  The visualization export context.
 */
export async function htmlToImageSvgExporter(
    context: VisualizationExportContext
): Promise<void> {
    const svg = await resolveVisualizationExportSvg(context);

    Device.downloadTextFile(
        getVisualizationExportName(context),
        new XMLSerializer().serializeToString(svg),
        "svg"
    );
}

/**
 * Finds an svg element and exports it to an svg image. If no svg element exists
 * in the root or if multiple exist, throws an error.
 * Uses browser-native capability instead of html-to-image.
 * @param context The visualization export context
 */
export async function liteSvgExporter(
    context: VisualizationExportContext
): Promise<void> {

    const exportRoot = context.visualization.getExportRoot?.(context.root)
        ?? context.root;
    const svgCandidates = exportRoot.querySelectorAll("svg");

    if (svgCandidates.length === 0) {
        throw new Error("No svg element found. Cannot export.");
    }

    if (svgCandidates.length > 1) {
        throw new Error("Multiple svg elements found. Cannot export.");
    }

    const svg = svgCandidates[0].cloneNode(true) as SVGSVGElement;
    addClassificationMarking(svg, context.app);

    const svgText = new XMLSerializer().serializeToString(svg);
    const blob = new Blob([svgText], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = getVisualizationExportName(context) + ".svg";
    a.click();
    URL.revokeObjectURL(url);
}

/**
 * Resolves the exported file name for a visualization.
 * @param context
 *  The visualization export context.
 * @returns
 *  The export file name without an extension.
 */
function getVisualizationExportName(
    context: VisualizationExportContext
): string {
    const sourceName = context.app.activeEditor.file.canvas.properties.toString()
        || "attack-flow";
    const exportName = typeof context.visualization.exportName === "function"
        ? context.visualization.exportName(context.app)
        : context.visualization.exportName
            ?? context.visualization.title;
    return sanitizeFileName(`${sourceName} - ${exportName}`);
}

/**
 * Converts an SVG data URL into SVG file contents.
 * @param dataUrl
 *  The data URL to decode.
 * @returns
 *  The SVG file contents.
 */
function svgDataUrlToText(dataUrl: string): string {
    const parts = dataUrl.split(",", 2);
    if (parts.length !== 2) {
        throw new Error("Unable to decode SVG export.");
    }
    const [prefix, content] = parts;
    return prefix.includes(";base64")
        ? atob(content)
        : decodeURIComponent(content);
}

/**
 * Removes characters that are unsafe for downloaded file names.
 * @param value
 *  The file name to sanitize.
 * @returns
 *  A safe file name.
 */
function sanitizeFileName(value: string): string {
    return value
        .replace(/[\\/:*?"<>|]+/g, "-")
        .replace(/\s+/g, " ")
        .trim();
}
