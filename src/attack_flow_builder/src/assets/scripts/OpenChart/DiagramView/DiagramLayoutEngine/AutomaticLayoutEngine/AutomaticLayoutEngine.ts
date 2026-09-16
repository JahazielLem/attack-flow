/**
 * This file implements a layout engine based on edge directions and utilizes D3 for collision forces.
 */
import { BlockView, CanvasView, LineView, type DiagramObjectView } from "../../DiagramObjectView";
import type { DiagramLayoutEngine } from "../DiagramLayoutEngine";
import * as d3 from "d3";
import {
    buildGraph,
    type CardinalDirection,
    findRootNodes,
    getBoundingBox,
    getIncomingDirectionsWithParents,
    getSiblingsOnSameSide,
    identifyComponents,
    topologicalSort
} from "../LayoutHelpers";

const COMPONENT_MARGIN = 250;
const BLOCK_SPACING_HORIZONTAL = 500;
const VERTICAL_LEVEL_PADDING = 120;
const SIDE_CHILD_VERTICAL_PADDING = 40;
const COLLISION_RADIUS = 200;
const COLLISION_STRENGTH = 0.07;

// The source and target should be block instance strings.
interface GraphLink extends d3.SimulationLinkDatum<d3.SimulationNodeDatum> {
    source: string; target: string;
}

interface MyD3Node extends d3.SimulationNodeDatum {
    id: string;
    width: number;
    height: number;
}

interface xyPair {
    x: number; y: number;
}

interface SideChildGroup {
    parent: BlockView;
    children: BlockView[];
}

export class AutomaticLayoutEngine implements DiagramLayoutEngine {
    public run(objects: DiagramObjectView[]): void {
        const nodes = new Set<BlockView>();
        const lines = new Set<LineView>();

        const firstObject : CanvasView = objects[0] as CanvasView;

        for (const block of firstObject.blocks) {
            if (block instanceof BlockView) {
                block.calculateLayout();
                nodes.add(block);
            }
        }

        for (const line of firstObject.lines) {
            if (line instanceof LineView) {
                lines.add(line);
                if (line.source) { line.source.calculateLayout(); }
                if (line.target) { line.target.calculateLayout(); }
            }
        }

        const { graph } = buildGraph(nodes, lines);

        const components = identifyComponents(graph, nodes);

        let componentNum = 0;
        let componentOffset = 0;
        // Calculate positions for each component. Then offset the component as to not overlap with other components.
        for (const c of components) {
            this.positionNodes(c, lines);

            const bb = getBoundingBox(c);
            const width = (bb.maxX - bb.minX) + (COMPONENT_MARGIN * 2);
            componentOffset += width / 2;

            if (componentNum > 0) {
                for (const block of c) {
                    block.moveBy(componentOffset, 0);
                }
                componentOffset += width / 2;
            }

            componentNum += 1;
        }


        for (const block of nodes) {
            block.calculateLayout();
        }
        for (const line of lines) {
            line.calculateLayout();
        }
    }

    /**
     * Find root nodes which are not action nodes and flip their relationship so they are treated as children instead of parents
     * where applicable.
     * @param graph The graph as an adjacency list of outgoing edges.
     * @param incomingEdges The graph as an adjacency list of incoming edges.
     */
    private flipNonActionRoots(
        graph: Map<BlockView, Set<BlockView>>,
        incomingEdges: Map<BlockView, Set<BlockView>>
    ): void {
        // Treat only Attack Flow action nodes as true roots. Non-action roots
        // (e.g., conditions or any other block type) should be flipped so that
        // they become children of their current children.
        const isActionNode = (node: BlockView) => node.id === "action";

        // Iteratively flip non-allowed roots with children until convergence
        const maxIterations = Math.max(1, graph.size * 2);
        let iterations = 0;
        while (iterations < maxIterations) {
            let flippedThisPass = 0;

            const roots = findRootNodes(graph, incomingEdges);
            const rootsToFlip: BlockView[] = [];

            for (const r of roots) {
                const children = graph.get(r) ?? new Set<BlockView>();
                if (!isActionNode(r) && children.size > 0) {
                    rootsToFlip.push(r);
                }
            }

            if (rootsToFlip.length === 0) { break; }

            for (const root of rootsToFlip) {
                const children = new Set<BlockView>(graph.get(root) ?? []);
                if (children.size === 0) { continue; } // isolated non-action root: leave as-is

                // Remove existing edges root -> child and child's incoming from root
                for (const child of children) {
                    graph.get(root)?.delete(child);
                    incomingEdges.get(child)?.delete(root);
                }

                // Add flipped edges child -> root and root's incoming from child
                for (const child of children) {
                    let outgoingFromChild = graph.get(child);
                    if (!outgoingFromChild) {
                        outgoingFromChild = new Set<BlockView>();
                        graph.set(child, outgoingFromChild);
                    }
                    outgoingFromChild.add(root);

                    let incomingToRoot = incomingEdges.get(root);
                    if (!incomingToRoot) {
                        incomingToRoot = new Set<BlockView>();
                        incomingEdges.set(root, incomingToRoot);
                    }
                    incomingToRoot.add(child);
                }

                flippedThisPass += 1;
            }

            iterations += 1;
            if (flippedThisPass === 0) { break; }
        }
    }

    /**
     * Assign xy positions to nodes.
     * @param nodes set of blocks
     * @param lines set of lines
     */
    private positionNodes(nodes: Set<BlockView>, lines: Set<LineView>): void {
        const { graph, incomingEdges } = buildGraph(nodes, lines);

        this.flipNonActionRoots(graph, incomingEdges);

        const rootNodes = findRootNodes(graph, incomingEdges);
        const sortedNodes = topologicalSort(graph, incomingEdges, rootNodes);
        const instancesToNodes : { [key: string] : BlockView } = {};

        const d3Links : GraphLink[] = [];
        for (const [parent, children] of graph) {
            for (const c of children) {
                d3Links.push({
                    source: parent.instance,
                    target: c.instance
                });
            }
        }

        const initialPositions = new Map<BlockView, xyPair>();
        const rootPositions = new Set<string>();
        const sideChildren = new Set<BlockView>();
        const lockedCenterNodes = new Set<BlockView>();
        for (const s of sortedNodes) {
            const parentsAndDirections = getIncomingDirectionsWithParents(s, incomingEdges);

            if (parentsAndDirections.size < 1 && s.id === "action") {
                lockedCenterNodes.add(s);
            }

            const totalParentPos = { x: 0, y: 0 };
            const offset = { x: 0, y: 0 };
            const offsetDirections = new Set<CardinalDirection>();
            for (const [key, dir] of parentsAndDirections) {
                const parentPos = initialPositions.get(key);

                if (parentPos) {
                    totalParentPos.x += parentPos.x;
                    totalParentPos.y += parentPos.y;
                }

                switch (dir) {
                    case "n":
                    case "nnw":
                    case "nne":
                        offsetDirections.add("n");
                        break;
                    case "s":
                    case "ssw":
                    case "sse":
                        offsetDirections.add("s");
                        break;
                    case "e":
                    case "ese":
                    case "ene":
                        offsetDirections.add("e");
                        break;
                    case "w":
                    case "wsw":
                    case "wnw":
                        offsetDirections.add("w");
                        break;
                    default:
                        console.warn("Something wrong with parent direction.");
                        break;
                }
            }

            for (const dir of offsetDirections) {
                switch (dir) {
                    case "n":
                        offset.y -= 1;
                        break;
                    case "s":
                        offset.y += 1;
                        break;
                    case "e":
                        offset.x += 1;
                        sideChildren.add(s);
                        break;
                    case "w":
                        offset.x -= 1;
                        sideChildren.add(s);
                        break;
                    default:
                        console.warn("Something wrong with parent direction.");
                        break;
                }
            }

            let avgParentPos = {
                x: 0,
                y: 0
            };
            if (parentsAndDirections.size) {
                avgParentPos = {
                    x: totalParentPos.x / parentsAndDirections.size,
                    y: totalParentPos.y / parentsAndDirections.size
                };
            }

            const position = {
                x: avgParentPos.x + offset.x,
                y: avgParentPos.y + offset.y
            };

            // If node has only one parent, offset the node based on the parent anchor it connects to.
            // to make room for other siblings.
            if (parentsAndDirections.size === 1) {
                const [parent] = parentsAndDirections.keys();
                const dir = parentsAndDirections.get(parent) as CardinalDirection;

                const siblingsOnSameSide = getSiblingsOnSameSide(graph, incomingEdges, parent, s);
                // If there is only one node on a side, keep it centered.
                if (siblingsOnSameSide.size < 1) {
                    if (["ssw", "s", "sse"].includes(dir)) {
                        lockedCenterNodes.add(s);
                    }
                } else {
                    if (dir === "nnw" || dir === "ssw") {
                        position.x -= 1;
                    } else if (dir === "nne" || dir === "sse") {
                        position.x += 1;
                    } else if (dir === "wnw" || dir === "ene") {
                        position.y -= 1;
                    } else if (dir === "wsw" || dir === "ese") {
                        position.y += 1;
                    }
                }
            }


            // Offset the node if it conflicts with sibling positions.
            for (const [key, dir] of parentsAndDirections) {
                const siblingsOnSameSide = getSiblingsOnSameSide(graph, incomingEdges, key, s);
                const knownPositions = new Set<string>();
                for (const sib of siblingsOnSameSide) {
                    const sibPos = initialPositions.get(sib);
                    if (sibPos) {
                        knownPositions.add(`${sibPos.x} ${sibPos.y}`);
                    }
                }

                let loopNumber = 0;
                while (true) {
                    if (!knownPositions.has(`${position.x} ${position.y}`)) {
                        break;
                    }

                    const even = loopNumber % 2 == 0;
                    // Alternate between incrementing and decrementing to achieve centering.
                    const increment = (even ? 1 : -1) * (loopNumber + 1);
                    if (dir === "n" || dir === "s") {
                        position.x += increment;
                    } else if (dir === "e" || dir === "w") {
                        position.y += increment;
                    } else if (dir === "nnw" || dir === "ssw") {
                        position.x -= 1;
                    } else if (dir === "nne" || dir === "sse") {
                        position.x += 1;
                    } else if (dir === "wnw" || dir === "ene") {
                        position.y -= 1;
                    } else if (dir === "wsw" || dir === "ese") {
                        position.y += 1;
                    }
                    loopNumber += 1;
                }

            }

            // Push other roots to the right.
            if (parentsAndDirections.size == 0) {
                let positionKey = `${position.x} ${position.y}`;
                while (rootPositions.has(positionKey)) {
                    position.x += 1;
                    positionKey = `${position.x} ${position.y}`;
                }
                rootPositions.add(positionKey);
            }

            initialPositions.set(s, position);
        }

        const d3Nodes : MyD3Node[] = [];

        // Pull side children toward parent before applying collision force.
        for (const sideChild of sideChildren) {
            const parents : Set<BlockView> | undefined = incomingEdges.get(sideChild);
            // Only pull if there is one parent.
            if (!parents || parents.size < 1 || parents.size > 1) { continue; }
            const firstParent = [...parents][0];
            const firstParentPos = initialPositions.get(firstParent) as xyPair;
            const childPos = initialPositions.get(sideChild) as xyPair;
            const diff = {
                x: childPos.x - firstParentPos.x,
                y: childPos.y - firstParentPos.y
            };
            const childNewPos = {
                x: firstParentPos.x + diff.x / 4,
                y: firstParentPos.y + diff.y / 4
            };
            initialPositions.set(sideChild, childNewPos);
        }

        const yPositions = this.computeVerticalPositions(initialPositions);
        const sideChildYOverrides = this.computeSideChildYPositions(
            sideChildren,
            incomingEdges,
            initialPositions,
            yPositions
        );

        // Initialize d3 nodes from calculated positions.
        for (const [key, value] of initialPositions) {
            instancesToNodes[key.instance] = key;
            const y = sideChildYOverrides.get(key) ?? yPositions.get(value.y) ?? 0;
            if (lockedCenterNodes.has(key)) {
                d3Nodes.push({
                    id: key.instance,
                    fx: value.x * BLOCK_SPACING_HORIZONTAL,
                    fy: y,
                    width: key.face.boundingBox.width,
                    height: key.face.boundingBox.height
                });
            } else {
                d3Nodes.push({
                    id: key.instance,
                    x: value.x * BLOCK_SPACING_HORIZONTAL,
                    fy: y,
                    width: key.face.boundingBox.width,
                    height: key.face.boundingBox.height
                });
            }

        }

        // Apply collision force with d3 simulation.
        const simulation = d3.forceSimulation(d3Nodes)
            .force("collide", d3.forceCollide(COLLISION_RADIUS).strength(COLLISION_STRENGTH).iterations(2))
            .stop();

        for (let i = 0; i < 200; i++) {
            simulation.tick();
        }

        // Use simulation results to position actual blocks on the canvas.
        for (const d3_node of d3Nodes) {
            const node = instancesToNodes[d3_node.id];
            node.moveTo(d3_node.x ?? 0, d3_node.y ?? 0);
        }

    }

    /**
     * Convert logical y-levels into concrete pixel positions using the maximum
     * measured height at each level instead of a fixed vertical step.
     */
    private computeVerticalPositions(
        initialPositions: Map<BlockView, xyPair>
    ): Map<number, number> {
        const levelHeights = new Map<number, number>();
        for (const [node, position] of initialPositions) {
            const height = node.face.boundingBox.height;
            const current = levelHeights.get(position.y) ?? 0;
            levelHeights.set(position.y, Math.max(current, height));
        }

        const levels = [...levelHeights.keys()].sort((a, b) => a - b);
        const yPositions = new Map<number, number>();

        let previousLevel: number | undefined;
        let previousY = 0;
        for (const level of levels) {
            if (previousLevel === undefined) {
                yPositions.set(level, 0);
                previousLevel = level;
                continue;
            }

            const previousHeight = levelHeights.get(previousLevel) ?? 0;
            const currentHeight = levelHeights.get(level) ?? 0;
            const separation = (previousHeight / 2) + (currentHeight / 2) + VERTICAL_LEVEL_PADDING;
            previousY += separation;

            yPositions.set(level, previousY);
            previousLevel = level;
        }

        return yPositions;
    }

    /**
     * Stack children attached on the left/right of a parent around the parent's
     * center line so they stay visually associated with that node instead of
     * being spread across global vertical ranks.
     */
    private computeSideChildYPositions(
        sideChildren: Set<BlockView>,
        incomingEdges: Map<BlockView, Set<BlockView>>,
        initialPositions: Map<BlockView, xyPair>,
        yPositions: Map<number, number>
    ): Map<BlockView, number> {
        const groups = new Map<string, SideChildGroup>();

        for (const child of sideChildren) {
            const parents = incomingEdges.get(child);
            if (!parents || parents.size !== 1) {
                continue;
            }

            const parent = [...parents][0];
            const dir = getIncomingDirectionsWithParents(child, incomingEdges).get(parent);
            if (!dir || !this.isSideDirection(dir)) {
                continue;
            }

            const key = `${parent.instance}:${this.sideDirectionKey(dir)}`;
            let group = groups.get(key);
            if (!group) {
                group = { parent, children: [] };
                groups.set(key, group);
            }
            group.children.push(child);
        }

        const overrides = new Map<BlockView, number>();

        for (const group of groups.values()) {
            group.children.sort((a, b) => {
                const posA = initialPositions.get(a);
                const posB = initialPositions.get(b);
                if (posA && posB && posA.y !== posB.y) {
                    return posA.y - posB.y;
                }
                return a.instance.localeCompare(b.instance);
            });

            const parentPos = initialPositions.get(group.parent);
            if (!parentPos) {
                continue;
            }

            const parentY = yPositions.get(parentPos.y) ?? 0;
            const totalHeight = group.children.reduce((sum, child) => {
                return sum + child.face.boundingBox.height;
            }, 0);
            const totalPadding = SIDE_CHILD_VERTICAL_PADDING * Math.max(0, group.children.length - 1);

            let cursorY = parentY - ((totalHeight + totalPadding) / 2);
            for (const child of group.children) {
                const childHeight = child.face.boundingBox.height;
                const centerY = cursorY + (childHeight / 2);
                overrides.set(child, centerY);
                cursorY += childHeight + SIDE_CHILD_VERTICAL_PADDING;
            }
        }

        return overrides;
    }

    private isSideDirection(dir: CardinalDirection): boolean {
        return ["e", "ene", "ese", "w", "wnw", "wsw"].includes(dir);
    }

    private sideDirectionKey(dir: CardinalDirection): "e" | "w" {
        if (["w", "wnw", "wsw"].includes(dir)) {
            return "w";
        }
        return "e";
    }
}
