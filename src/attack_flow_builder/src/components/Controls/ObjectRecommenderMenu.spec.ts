// @vitest-environment jsdom

import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import ObjectRecommenderMenu from "./ObjectRecommenderMenu.vue";
import type { ObjectRecommendation, ObjectRecommendations, ObjectRecommender } from "@OpenChart/DiagramEditor";

const ACTION: ObjectRecommendation = {
    id: "action",
    color: "#000000",
    name: "action",
    subtitle: "Action"
};

function createDeferred<T>() {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>(r => {
        resolve = r;
    });
    return { promise, resolve };
}

function mountMenu(recommender: ObjectRecommender) {
    return mount(ObjectRecommenderMenu, {
        props: { recommender },
        global: {
            stubs: {
                ScrollListBox: {
                    props: ["items"],
                    emits: ["scroll"],
                    mounted() {
                        this.$emit("scroll", 0);
                    },
                    template: `
                        <div>
                            <slot
                                v-for="item in items"
                                name="item"
                                :item="item"
                            />
                        </div>
                    `
                }
            }
        }
    });
}

function createRecommender(items: ObjectRecommendation[]): ObjectRecommender {
    return {
        getRecommendations: vi.fn(async () => ({ items }))
    } as unknown as ObjectRecommender;
}

describe("ObjectRecommenderMenu", () => {
    it("shows a loading icon until recommendations are available", async () => {
        const recommendations = createDeferred<ObjectRecommendations>();
        const recommender = {
            getRecommendations: vi.fn(() => recommendations.promise)
        } as unknown as ObjectRecommender;

        const wrapper = mountMenu(recommender);

        expect(wrapper.find("[role='status']").exists()).toBe(true);
        expect(wrapper.find(".loading").exists()).toBe(true);

        recommendations.resolve({ items: [ACTION] });
        await flushPromises();

        expect(wrapper.find("[role='status']").exists()).toBe(false);
        expect(wrapper.text()).toContain("action");
    });

    it("emits the selected recommendation when clicked", async () => {
        const wrapper = mountMenu(createRecommender([ACTION]));
        await flushPromises();

        await wrapper.find(".recommendation").trigger("click");

        expect(wrapper.emitted("select")?.[0]).toEqual([ACTION]);
    });

    it("emits the active recommendation when Enter is pressed", async () => {
        const wrapper = mountMenu(createRecommender([ACTION]));
        await flushPromises();

        await wrapper.find(".object-recommender-menu-control").trigger("keydown", {
            key: "Enter"
        });

        expect(wrapper.emitted("select")?.[0]).toEqual([ACTION]);
    });
});
