import { describe, expect, it } from "vitest";
import type { ApplicationStore } from "@/stores/ApplicationStore";
import { ShowSplashMenu } from "./ShowSplashMenu";

describe("ShowSplashMenu", () => {
    it("opens the requested splash screen", async () => {
        const context = {
            splashMenuMode: "home",
            settings: {
                view: {
                    splash_menu: {
                        display_menu: false
                    }
                }
            }
        } as ApplicationStore;

        await new ShowSplashMenu(context, "ai-generation").execute();

        expect(context.splashMenuMode).toBe("ai-generation");
        expect(context.settings.view.splash_menu.display_menu).toBe(true);
    });
});
