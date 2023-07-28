/**
 * Represents a logger object which is used to log messages in the library.
 */
export interface Logger {
    trace?: (...content: any[]) => void;
    debug: (...content: any[]) => void;
    info: (...content: any[]) => void;
    warn: (...content: any[]) => void;
    error: (...content: any[]) => void;
}

/**
 * Implementation of Logger which does not log any message.
 */
export class NoOpLogger implements Logger {
    public trace() {}
    public debug() {}
    public info() {}
    public warn() {}
    public error() {}
}