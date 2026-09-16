// @vitest-environment jsdom

import { beforeAll, describe, expect, it } from "vitest";

let addClassificationMarking: typeof import("./Visualization").addClassificationMarking;

beforeAll(async () => {
    Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
        configurable: true,
        value: () => ({
            font: "",
            measureText: () => ({ width: 0 })
        })
    });

    ({ addClassificationMarking } = await import("./Visualization"));
});

describe("addClassificationMarking", () => {
    it("adds a centered classification banner with group text", () => {
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("viewBox", "0 0 400 200");
        const contentRect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        contentRect.setAttribute("x", "10");
        contentRect.setAttribute("y", "10");
        contentRect.setAttribute("width", "50");
        contentRect.setAttribute("height", "50");
        svg.append(contentRect);

        const app = {
            activeEditor: {
                file: {
                    canvas: {
                        properties: {
                            get: (key: string) => key === "classification"
                                ? {
                                    get: (property: string) => {
                                        if (property === "marking") {
                                            return {
                                                value: "tlp-red",
                                                toString: () => "TLP:RED"
                                            };
                                        }

                                        if (property === "group") {
                                            return { value: "CTID" };
                                        }

                                        return undefined;
                                    }
                                }
                                : undefined
                        }
                    }
                }
            }
        };

        const result = addClassificationMarking(svg, app as never);
        const banner = result.querySelector("[data-classification-marking='true']");
        const contentGroup = result.querySelector("[data-classification-content='true']");
        const rect = banner?.querySelector("rect");
        const text = banner?.querySelector("text");

        expect(banner).not.toBeNull();
        expect(result.getAttribute("viewBox")).toBe("0 0 400 224");
        expect(contentGroup?.getAttribute("transform")).toBe("translate(0 24)");
        expect(rect?.getAttribute("fill")).toBe("#000000");
        expect(rect?.getAttribute("y")).toBe("0");
        expect(text?.textContent).toBe("TLP:RED:CTID");
        expect(text?.getAttribute("y")).toBe("15");
        expect(text?.getAttribute("fill")).toBe("#FF2B2B");
        expect(text?.getAttribute("text-anchor")).toBe("middle");
    });

    it("does not add a banner when classification is absent", () => {
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("viewBox", "0 0 400 200");

        const app = {
            activeEditor: {
                file: {
                    canvas: {
                        properties: {
                            get: () => undefined
                        }
                    }
                }
            }
        };

        const result = addClassificationMarking(svg, app as never);
        expect(result.querySelector("[data-classification-marking='true']")).toBeNull();
    });
});
