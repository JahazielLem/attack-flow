import { AppCommand } from "../AppCommand";
import type { ApplicationStore, SplashMenuMode } from "@/stores/ApplicationStore";

export class ShowSplashMenu extends AppCommand {

    /**
     * The application context.
     */
    public readonly context: ApplicationStore;

    /**
     * The splash screen to display.
     */
    public readonly mode: SplashMenuMode;


    /**
     * Display the splash menu.
     * @param context
     *  The application context.
     * @param mode
     *  The splash screen to display.
     */
    constructor(context: ApplicationStore, mode: SplashMenuMode = "home") {
        super();
        this.context = context;
        this.mode = mode;
    }


    /**
     * Executes the command.
     */
    public async execute(): Promise<void> {
        this.context.splashMenuMode = this.mode;
        this.context.settings.view.splash_menu.display_menu = true;
    }

}
