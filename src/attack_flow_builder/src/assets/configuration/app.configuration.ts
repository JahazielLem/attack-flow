import AttackFlowValidator from "./AttackFlowValidator/AttackFlowValidator.ts";
import AttackFlowPublisher from "./AttackFlowPublisher/AttackFlowPublisher.ts";
import AttackFlowFilePreprocessor from "./AttackFlowFilePreprocessor/AttackFlowFilePreprocessor.ts";
import AttackFlowCommandProcessor from "./AttackFlowCommandProcessor/AttackFlowCommandProcessor.ts";
import SpartaEnums from "./AttackFlowTemplates/MitreSparta.ts";
import SpaceShieldEnums from "./AttackFlowTemplates/SpaceShield.ts";
import { CatppuccinTheme } from "./AttackFlowThemes/CatppuccinTheme.ts";
import { AttackFlowRecommender } from "./AttackFlowRecommender/AttackFlowRecommender.ts";
import { TacticTableVisualization } from "./AttackFlowVisualizations/TacticTableVisualization.ts";
import { TimelineVisualization } from "./AttackFlowVisualizations/TimelineVisualization.ts";
import { TreemapVisualization } from "./AttackFlowVisualizations/TreemapVisualization.ts";
import { PresentationVisualization } from "./AttackFlowVisualizations/PresentationVisualization.ts";
import { MatrixViewVisualization } from "./AttackFlowVisualizations/MatrixViewVisualization.ts";
import { IOCTableVisualization } from "./AttackFlowVisualizations/IOCTableVisualization.ts";
import { DarkTheme } from "./AttackFlowThemes/DarkTheme.ts";
import { BlogTheme } from "./AttackFlowThemes/BlogTheme.ts";
import { LightTheme } from "./AttackFlowThemes/LightTheme.ts";
import { CtidLogo, CtidPwnsatLogo, CtidSpartaLogo } from "./Images";
import {
    AttackFlow,
    AttackFlowObjects,
    BaseObjects,
    StixObjects,
    StixObservables
} from "./AttackFlowTemplates";
import { BasicVisualizationModal } from "../scripts/Application/Visualization";
import type { AppConfiguration } from "../scripts/Application/Configuration/AppConfiguration";

const configuration: AppConfiguration = {

    /**
     * The application's name.
     */
    application_name: "Attack Flow Builder · Space Frameworks by PWNSAT",

    /**
     * The application's icon.
     */
    application_icon: CtidPwnsatLogo,

    /**
     * The application file type's name.
     */
    file_type_name: "Attack Flow",

    /**
     * The application file type's extension.
     */
    file_type_extension: "afb",

    /**
     * The application's splash screen configuration.
     */
    splash: {
        organization: CtidLogo,
        sparta: CtidSpartaLogo,
        framework_versions: [
            {
                name: "SPARTA",
                version: SpartaEnums.version,
                documentation_url: "https://sparta.aerospace.org/resources/user-guide",
                description: "Space Attack Research and Tactic Analysis"
            },
            {
                name: "SPACE-SHIELD",
                version: SpaceShieldEnums.version,
                documentation_url: "https://spaceshield.esa.int/",
                description: "ESA knowledge base for space systems cybersecurity"
            }
        ],
        new_file: {
            title: "New Flow",
            description: "Create a blank flow."
        },
        open_file: {
            title: "Open Flow",
            description: "Open an existing flow."
        },
        generate_flow: {
            title: "Generate Flow",
            description: "Generate a flow out of a security incident report."
        },
        import_stix: {
            title: "Import STIX",
            description: "Import a STIX bundle."
        },
        help_links: [
            {
                title: "Example Flows",
                description: "Visit a list of example Flows.",
                url: "https://jahaziellem.github.io/attack-flow/example_flows/"
            },
            {
                title: "Builder Help",
                description: "Read the builder's user guide.",
                url: "https://jahaziellem.github.io/attack-flow/builder/"
            }
        ]
    },

    /**
     * The application's schema.
     */
    schema: {
        id: "attack_flow_v2",
        canvas: AttackFlow,
        templates: [
            ...AttackFlowObjects,
            ...StixObjects,
            ...StixObservables,
            ...BaseObjects
        ]
    },

    /**
     * The application's themes.
     */
    themes: [
        CatppuccinTheme,
        BlogTheme,
        DarkTheme,
        LightTheme
    ],

    /**
     * The application's menus.
     */
    menus: {
        help_menu: {
            help_links: [
                {
                    text: "Attack Flow Website",
                    url: "https://jahaziellem.github.io/attack-flow/"
                },
                {
                    text: "Attack Flow Builder Help",
                    url: "https://jahaziellem.github.io/attack-flow/builder/"
                },
                {
                    text: "MITRE ATT&CK Framework",
                    url: "https://attack.mitre.org/"
                },
                {
                    text: "Base Project GitHub Repository",
                    url: "https://github.com/center-for-threat-informed-defense/attack-flow"
                },
                {
                    text: "Fork GitHub Repository",
                    url: "https://github.com/JahazielLem/attack-flow"
                },
                {
                    text: "SPARTA Documentation",
                    url: "https://sparta.aerospace.org/resources/user-guide"
                },
                {
                    text: "SPACE-SHIELD Documentation",
                    url: "https://spaceshield.esa.int/"
                },
                {
                    text: "SPARTA STIX Repository",
                    url: "https://github.com/JahazielLem/attack-stix-data"
                },
                {
                    text: "Change Log",
                    url: "https://github.com/JahazielLem/attack-flow/releases"
                }
            ]
        }
    },

    validator: {
        create: () => new AttackFlowValidator()
    },

    publisher: {
        create: () => new AttackFlowPublisher(),
        menuText: "Export STIX File"
    },

    filePreprocessor: {
        create: () => new AttackFlowFilePreprocessor()
    },

    cmdProcessor: {
        create: () => new AttackFlowCommandProcessor()
    },

    recommender: {
        create: () => new AttackFlowRecommender()
    },

    visualizationModal: {
        create: visualizations => new BasicVisualizationModal(visualizations)
    },

    visualizations: [
        TacticTableVisualization,
        PresentationVisualization,
        MatrixViewVisualization,
        TimelineVisualization,
        TreemapVisualization,
        IOCTableVisualization
    ]

};

export default configuration;
