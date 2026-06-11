import type { StixObservableObjectBase } from "./StixObservableObjectBase";

export interface RawIQCapture extends StixObservableObjectBase<"x-raw-iq-capture"> {
    name?: string;
    file_name?: string;
    frequency_hz?: number;
    sample_rate_hz?: number;
    modulation?: string;
    capture_date?: string;
    description?: string;
}
