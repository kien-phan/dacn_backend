export interface SyntaxErrorWithStatus extends SyntaxError {
    status?: number;
    body?: any;
}

export interface UserJwtInterface {
    id: string;
    email: string;
    phone: string;
    username: string;
    iat?: number;
    exp?: number;
}

export type FileQuantityType = "single" | "multiple";
