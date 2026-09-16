const KEYS = {
    THEME_ID: "AFB:THEME_ID"
};

const DEFAULT_THEME_ID = "catppuccin_theme";

export default {
    getThemeId(): string {
        return localStorage.getItem(KEYS.THEME_ID) || DEFAULT_THEME_ID;
    },
    setThemeId(value: string) {
        localStorage.setItem(KEYS.THEME_ID, value);
    }
};
