import * as EditorCommands from "@OpenChart/DiagramEditor/Commands";
import { SetStringProperty, SetTupleSubproperty } from "@OpenChart/DiagramEditor/Commands/index.commands";
import { SynchronousEditorCommand } from "@OpenChart/DiagramEditor";
import { RootProperty, StringProperty, TupleProperty } from "@OpenChart/DiagramModel";
import type { SynchronousCommandProcessor } from "@OpenChart/DiagramEditor";

export class AttackFlowCommandProcessor implements SynchronousCommandProcessor {

    /**
     * Processes a {@link SynchronousEditorCommand}.
     * @param cmd
     *  The command about to be executed.
     * @returns
     *  The command to execute in its place.
     */
    public process(cmd: SynchronousEditorCommand): SynchronousEditorCommand | undefined {
        if (!this.isSettingTtp(cmd)) {
            return undefined;
        }
        // Get root property
        const properties = cmd.property.parent;
        if (!(properties instanceof RootProperty)) {
            return undefined;
        }
        // Get name property
        const name = properties.get("name", StringProperty);
        if (name === undefined) {
            return undefined;
        }
        const value = name.toString();
        // Set name
        let nextName: string | null = null,
            fallbackName: string | null = null,
            previousName: string | null = null;
        if (this.isSettingTactic(cmd.nextValue)) {
            nextName = this.getSelectedName(cmd.property, "tactic", cmd.nextValue.nextValue);
            fallbackName = this.getSelectedName(cmd.property, "technique")
                ?? this.getSelectedName(cmd.property, "subtechnique");
            previousName = this.getSelectedName(cmd.property, "tactic");
            if (value === nextName || value === previousName) {
                return this.setNameCmd(cmd, name, nextName);
            }
        } else if (this.isSettingTechnique(cmd.nextValue)) {
            nextName = this.getSelectedName(cmd.property, "technique", cmd.nextValue.nextValue);
            fallbackName = this.getSelectedName(cmd.property, "subtechnique")
                ?? this.getSelectedName(cmd.property, "tactic");
            previousName = this.getSelectedName(cmd.property, "technique");
            if (value === fallbackName || value === previousName) {
                return this.setNameCmd(cmd, name, nextName);
            }
        } else if (this.isSettingSubtechnique(cmd.nextValue)) {
            nextName = this.getSelectedName(cmd.property, "subtechnique", cmd.nextValue.nextValue);
            fallbackName = this.getSelectedName(cmd.property, "technique")
                ?? this.getSelectedName(cmd.property, "tactic");
            previousName = this.getSelectedName(cmd.property, "subtechnique");
            if (value === fallbackName || value === previousName) {
                return this.setNameCmd(cmd, name, nextName);
            }
        }
        if (!name.isDefined() && (nextName || fallbackName)) {
            return this.setNameCmd(cmd, name, nextName ?? fallbackName);
        }
    }

    /**
     * Creates a set name command.
     * @param cmd
     *  The existing {@link SetTupleSubproperty}.
     * @param prop
     *  The name property.
     * @param value
     *  The name property's new value.
     */
    public setNameCmd(cmd: SetTupleSubproperty, prop: StringProperty, value: string | null) {
        const bundle = EditorCommands.newGroupCommand();
        bundle.do(cmd);
        bundle.do(EditorCommands.setStringProperty(prop, value));
        return bundle;
    }

    /**
     * Gets the display name for a selected tuple value.
     * @param prop
     *  The tuple property.
     * @param key
     *  The tuple key.
     * @param value
     *  The field's next value.
     * @returns
     *  The selected object's display name.
     */
    public getSelectedName(
        prop: TupleProperty,
        key: "tactic" | "technique" | "subtechnique",
        value?: string | null
    ): string | null {
        const field = prop.get(key, StringProperty);
        if (!field) {
            return null;
        }
        if (value === undefined) {
            value = field.value;
        }
        if (value === null) {
            return null;
        }
        const displayText = field.options?.value.get(value)?.toString();
        if (displayText === undefined) {
            return null;
        }
        return displayText
            .replace(/^\[[^\]]+\]\s+/, "")
            .replace(/^\S+\s+/, "")
            .trim();
    }

    /**
     * Tests if a command is setting a TTP.
     * @param cmd
     *  The command.
     * @returns
     *  True if the command is setting a TTP, false otherwise.
     */
    private isSettingTtp(cmd: SynchronousEditorCommand): cmd is SetTupleSubproperty {
        return cmd instanceof SetTupleSubproperty
            && cmd.property.id === "ttp";
    }

    /**
     * Tests if a command is setting a tactic property.
     * @param cmd
     *  The command.
     * @returns
     *  True if the command is setting a tactic, false otherwise.
     */
    private isSettingTactic(cmd: SynchronousEditorCommand): cmd is SetStringProperty {
        return cmd instanceof SetStringProperty
            && cmd.property.id === "tactic";
    }

    /**
     * Tests if a command is setting a technique property.
     * @param cmd
     *  The command.
     * @returns
     *  True if the command is setting a technique, false otherwise.
     */
    private isSettingTechnique(cmd: SynchronousEditorCommand): cmd is SetStringProperty {
        return cmd instanceof SetStringProperty
            && cmd.property.id === "technique";
    }

    /**
     * Tests if a command is setting a subtechnique property.
     * @param cmd
     *  The command.
     * @returns
     *  True if the command is setting a subtechnique, false otherwise.
     */
    private isSettingSubtechnique(cmd: SynchronousEditorCommand): cmd is SetStringProperty {
        return cmd instanceof SetStringProperty
            && cmd.property.id === "subtechnique";
    }

}

export default AttackFlowCommandProcessor;
