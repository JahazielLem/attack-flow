import { describe, expect, it } from "vitest";
import { getDomainCodeFromLabel, getTacticNameFromLabel, getTechniqueNameFromLabel } from "./TTPFrameworkConstants";

describe("TTPFrameworkConstants", () => {
    it("extracts tactic names from supported framework labels", () => {
        expect(getTacticNameFromLabel("[ENT] TA0002 Execution"))
            .toBe("Execution");
        expect(getTacticNameFromLabel("[ATL] AML.TA0002 Reconnaissance"))
            .toBe("Reconnaissance");
        expect(getTacticNameFromLabel("[F3] F3.FA0001 Positioning"))
            .toBe("Positioning");
        expect(getTacticNameFromLabel("[D3F] Deceive"))
            .toBe("Deceive");
        expect(getTacticNameFromLabel("[SPA] ST0001 Reconnaissance"))
            .toBe("Reconnaissance");
        expect(getTacticNameFromLabel("[SSH] SSH.TA0001 Initial Access"))
            .toBe("Initial Access");
    });

    it("extracts technique names from supported framework labels", () => {
        expect(getTechniqueNameFromLabel("[ENT] T1059 Command and Scripting Interpreter"))
            .toBe("Command and Scripting Interpreter");
        expect(getTechniqueNameFromLabel("[ATL] AML.T0000 Search Open Technical Databases"))
            .toBe("Search Open Technical Databases");
        expect(getTechniqueNameFromLabel("[D3F] D3F-UGPH User Group Permissions"))
            .toBe("User Group Permissions");
        expect(getTechniqueNameFromLabel("[F3] F3.F1001 3DS Bypass"))
            .toBe("3DS Bypass");
        expect(getTechniqueNameFromLabel("[SPA] REC-0001.01 Gather Spacecraft Information"))
            .toBe("Gather Spacecraft Information");
        expect(getTechniqueNameFromLabel("[SSH] SSH.T2001.001 Telecommand Protocol Scanning"))
            .toBe("Telecommand Protocol Scanning");
    });

    it("recognizes both space frameworks for filtering and visualizations", () => {
        expect(getDomainCodeFromLabel("[SPA] REC-0001 Gather Information"))
            .toBe("SPA");
        expect(getDomainCodeFromLabel("[SSH] SSH.T2001 Active Scanning"))
            .toBe("SSH");
    });
});
