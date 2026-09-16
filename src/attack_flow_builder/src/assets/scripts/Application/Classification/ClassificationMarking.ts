/**
 * Formats classification marking text for export banners.
 * @param markingText
 *  The classification marking label.
 * @param groupText
 *  The optional classification group label.
 * @returns
 *  The formatted classification marking text.
 */
export function formatClassificationText(
    markingText: string,
    groupText?: string | null
): string {
    return groupText ? `${markingText}:${groupText}` : markingText;
}

/**
 * Resolves the text color for a classification marking banner.
 * @param markingText
 *  The classification marking label.
 * @returns
 *  The text color for the classification marking.
 */
export function getClassificationTextColor(markingText: string): string {
    switch (markingText) {
        case "TLP:RED":
            return "#FF2B2B";
        case "TLP:AMBER":
        case "TLP:AMBER+STRICT":
            return "#FFC000";
        case "TLP:GREEN":
        case "UNCLASSIFIED":
            return "#33FF00";
        default:
            return "#FFFFFF";
    }
}

/** Default horizontal padding inside canvas classification banners. */
const CANVAS_CLASSIFICATION_PADDING_X = 5;

/** Default vertical padding inside canvas classification banners. */
const CANVAS_CLASSIFICATION_PADDING_Y = 2;

/** XML namespace used when creating SVG classification marking nodes. */
const SVG_NS = "http://www.w3.org/2000/svg";

/** Default font size for SVG classification banners. */
const SVG_CLASSIFICATION_FONT_SIZE = 16;

/** Default horizontal padding inside SVG classification banners. */
const SVG_CLASSIFICATION_PADDING_X = 5;

/** Default vertical padding inside SVG classification banners. */
const SVG_CLASSIFICATION_PADDING_Y = 2;

/** Estimated text-width multiplier used to size SVG classification banners. */
const SVG_CLASSIFICATION_TEXT_WIDTH_FACTOR = 0.62;

/** Ratio used to position SVG text on its alphabetic baseline. */
const SVG_CLASSIFICATION_TEXT_BASELINE_RATIO = 0.8;

/** Default background color for canvas classification banners. */
const CANVAS_CLASSIFICATION_BACKGROUND_COLOR = "#000000";

/** Default text color for canvas classification banners. */
const CANVAS_CLASSIFICATION_TEXT_COLOR = "#FFFFFF";

/** Fallback text height used when canvas metrics do not report bounds. */
const CANVAS_CLASSIFICATION_FALLBACK_TEXT_HEIGHT = 16;

/** Options for drawing a classification marking onto a canvas export. */
export interface CanvasClassificationMarkingOptions {
    /** The text color for the classification marking. */
    textColor?: string;

    /** The background color for the classification marking banner. */
    backgroundColor?: string;
}

/** Options for creating a classification marking SVG banner. */
export interface SvgClassificationMarkingOptions {
    /** The text color for the classification marking. */
    textColor?: string;

    /** The x position for the banner background rectangle. */
    x?: number;

    /** The y position for the banner background rectangle. */
    y?: number;

    /** The background color for the classification marking banner. */
    backgroundColor?: string;
}

/** Resolved SVG viewport dimensions used for default banner placement. */
interface SvgClassificationViewport {
    /** Left edge of the SVG viewport. */
    x: number;

    /** Top edge of the SVG viewport. */
    y: number;

    /** Width of the SVG viewport. */
    width: number;
}

/** Resolves the viewport used to position SVG classification banners. */
function getSvgClassificationViewport(
    svg: SVGSVGElement
): SvgClassificationViewport {
    const viewBox = svg.getAttribute("viewBox");
    if (viewBox) {
        const [x, y, width] = viewBox.split(/[\s,]+/).map(Number);
        if ([x, y, width].every(Number.isFinite) && width > 0) {
            return { x, y, width };
        }
    }

    const widthMatch = svg.getAttribute("width")?.trim().match(
        /^([+-]?\d*\.?\d+)([%a-z]*)$/i
    );
    if (widthMatch && widthMatch[2] !== "%") {
        const width = Number(widthMatch[1]);
        if (width > 0) {
            return { x: 0, y: 0, width };
        }
    }

    try {
        const bbox = svg.getBBox();
        if (bbox.width > 0) {
            return { x: bbox.x, y: bbox.y, width: bbox.width };
        }
    } catch {
        // getBBox throws when the SVG is not rendered.
    }

    return { x: 0, y: 0, width: svg.clientWidth || 0 };
}

/** Resolves the text height to use when sizing a canvas marking banner. */
function getCanvasClassificationTextHeight(
    context: CanvasRenderingContext2D,
    metrics: TextMetrics
): number {
    const textHeight = metrics.actualBoundingBoxAscent
        + metrics.actualBoundingBoxDescent;
    if (textHeight > 0) {
        return textHeight;
    }

    const fontSize = context.font.match(/([+-]?\d*\.?\d+)px/i)?.[1];
    if (fontSize) {
        const parsedFontSize = Number(fontSize);
        if (parsedFontSize > 0) {
            return parsedFontSize;
        }
    }

    return CANVAS_CLASSIFICATION_FALLBACK_TEXT_HEIGHT;
}

/**
 * Draws a classification marking onto a raster export canvas.
 * @param context
 *  The canvas context that will receive the classification marking.
 * @param text
 *  The formatted classification marking text to render.
 * @param options
 *  Optional canvas drawing options for the classification marking.
 */
export function drawClassificationMarking(
    context: CanvasRenderingContext2D,
    text: string,
    options: CanvasClassificationMarkingOptions = {}
): void {
    context.save();
    context.setTransform(1, 0, 0, 1, 0, 0);
    context.textBaseline = "top";

    const textColor = options.textColor ?? CANVAS_CLASSIFICATION_TEXT_COLOR;
    const backgroundColor = options.backgroundColor
        ?? CANVAS_CLASSIFICATION_BACKGROUND_COLOR;
    const metrics = context.measureText(text);
    const textHeight = getCanvasClassificationTextHeight(context, metrics);
    const rectWidth = Math.ceil(
        metrics.width + (CANVAS_CLASSIFICATION_PADDING_X * 2)
    );
    const rectHeight = Math.ceil(
        textHeight + (CANVAS_CLASSIFICATION_PADDING_Y * 2)
    );
    const rectX = Math.round((context.canvas.width - rectWidth) / 2);

    context.fillStyle = backgroundColor;
    context.fillRect(rectX, 0, rectWidth, rectHeight);
    context.fillStyle = textColor;
    context.fillText(
        text,
        rectX + CANVAS_CLASSIFICATION_PADDING_X,
        CANVAS_CLASSIFICATION_PADDING_Y
    );
    context.restore();
}

/**
 * Creates an SVG group containing a classification marking banner.
 * @param svg
 *  The SVG the classification marking will be rendered within.
 * @param text
 *  The formatted classification marking text to render.
 * @param options
 *  Optional SVG creation options for the classification marking.
 * @returns
 *  The classification marking SVG group.
 */
export function createSvgClassificationMarking(
    svg: SVGSVGElement,
    text: string,
    options: SvgClassificationMarkingOptions = {}
): SVGGElement {
    const viewport = getSvgClassificationViewport(svg);
    const rectWidth = Math.ceil(
        (text.length * SVG_CLASSIFICATION_FONT_SIZE * SVG_CLASSIFICATION_TEXT_WIDTH_FACTOR)
        + (SVG_CLASSIFICATION_PADDING_X * 2)
    );
    const rectHeight = SVG_CLASSIFICATION_FONT_SIZE + (SVG_CLASSIFICATION_PADDING_Y * 2);
    const rectX = options.x
        ?? (viewport.x + ((viewport.width - rectWidth) / 2));
    const rectY = options.y ?? viewport.y;
    const textX = rectX + (rectWidth / 2);
    const textY = rectY
        + SVG_CLASSIFICATION_PADDING_Y
        + Math.round(SVG_CLASSIFICATION_FONT_SIZE * SVG_CLASSIFICATION_TEXT_BASELINE_RATIO);
    const textColor = options.textColor ?? CANVAS_CLASSIFICATION_TEXT_COLOR;
    const backgroundColor = options.backgroundColor
        ?? CANVAS_CLASSIFICATION_BACKGROUND_COLOR;
    const documentRoot = svg.ownerDocument ?? document;

    const group = documentRoot.createElementNS(SVG_NS, "g");
    group.setAttribute("data-classification-marking", "true");
    group.setAttribute("pointer-events", "none");

    const rect = documentRoot.createElementNS(SVG_NS, "rect");
    rect.setAttribute("x", String(rectX));
    rect.setAttribute("y", String(rectY));
    rect.setAttribute("width", String(rectWidth));
    rect.setAttribute("height", String(rectHeight));
    rect.setAttribute("fill", backgroundColor);

    const textElement = documentRoot.createElementNS(SVG_NS, "text");
    textElement.setAttribute("x", String(textX));
    textElement.setAttribute("y", String(textY));
    textElement.setAttribute("fill", textColor);
    textElement.setAttribute("font-size", String(SVG_CLASSIFICATION_FONT_SIZE));
    textElement.setAttribute("font-weight", "600");
    textElement.setAttribute("font-family", "sans-serif");
    textElement.setAttribute("text-anchor", "middle");
    textElement.setAttribute("dominant-baseline", "alphabetic");
    textElement.textContent = text;

    group.append(rect, textElement);
    return group;
}
