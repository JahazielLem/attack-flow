import type { StixObservableObjectBase } from "./StixObservableObjectBase";

/**
 * STIX 2.1 RadioFrequency.
 */
export interface RadioFrequency extends StixObservableObjectBase<"software"> {

    /**
     * Specifies the name of the software.
     */
    name: string;

    /**
     * Specifies the Frequency in MHz.
     */
    frequency?: string;

    /**
     * Specifies the Modulation.
     */
    modulation?: string;
}
