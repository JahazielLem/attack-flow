import { describe, expect, it } from "vitest";

import {

    formatLogSourceBlockLines,

    formatLogSourceEntry,

    logSourceKey,

    parseLogSourceKey

} from "./logSourceUtils";



describe("logSourceUtils", () => {

    it("round-trips log source keys", () => {

        const key = logSourceKey("WinEventLog:Sysmon", "EventCode=1");

        expect(parseLogSourceKey(key)).toEqual({

            name: "WinEventLog:Sysmon",

            channel: "EventCode=1"

        });

    });



    it("formats block lines with name-only bullets", () => {

        const key = logSourceKey("auditd:SYSCALL", "execve");

        expect(formatLogSourceBlockLines([key])).toEqual(["• auditd:SYSCALL"]);

        expect(formatLogSourceEntry(key)).toContain("name: auditd:SYSCALL");

        expect(formatLogSourceEntry(key)).toContain("channel: execve");

    });

});
