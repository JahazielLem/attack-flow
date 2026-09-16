// @vitest-environment jsdom

import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import SplashMenu from "./SplashMenu.vue";
import SpartaEnums from "@/assets/configuration/AttackFlowTemplates/MitreSparta";
import SpaceShieldEnums from "@/assets/configuration/AttackFlowTemplates/SpaceShield";

vi.hoisted(() => {
    window.matchMedia = () => ({
        matches: false, media: "", onchange: null,
        addEventListener: () => undefined, removeEventListener: () => undefined,
        addListener: () => undefined, removeListener: () => undefined,
        dispatchEvent: () => false
    });
});

vi.mock("@/stores/ApplicationStore", () => ({
    useApplicationStore: () => ({
        splashMenuMode: "home",
        activeEditor: { id: "active" },
        fileRecoveryBank: { files: new Map() }
    })
}));

vi.mock("@/assets/scripts/Application/Commands", () => ({}));
vi.mock("./AIGenerationSplashScreen.vue", () => ({
    default: { template: "<div />" }
}));

vi.mock("@OpenChart/Utilities/FontStore", () => ({
    GlobalFontStore: {
        loadFont: async () => undefined,
        getFont: () => ({
            measureWidth: () => 0,
            measure: () => ({ width: 0, ascent: 0, descent: 0, height: 0 }),
            wordWrap: (text: string) => [text]
        })
    }
}));

describe("SplashMenu framework references", () => {
    it("shows both installed space framework versions with official documentation links", () => {
        const wrapper = mount(SplashMenu);
        const sparta = wrapper.get("a[href=\"https://sparta.aerospace.org/resources/user-guide\"]");
        const spaceShield = wrapper.get("a[href=\"https://spaceshield.esa.int/\"]");

        expect(sparta.text()).toContain("SPARTA");
        expect(sparta.text()).toContain(`STIX catalog v${SpartaEnums.version}`);
        expect(spaceShield.text()).toContain("SPACE-SHIELD");
        expect(spaceShield.text()).toContain(`STIX catalog v${SpaceShieldEnums.version}`);
        expect(wrapper.findAll(".framework-link")).toHaveLength(2);

        wrapper.unmount();
    });
});
