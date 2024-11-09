export interface SyntaxErrorWithStatus extends SyntaxError {
    status?: number;
    body?: any;
}

export interface UserJwtInterface {
    id: string;
    email: string;
    isAdmin: boolean;
    isActive: boolean;
    iat?: number;
    exp?: number;
}
