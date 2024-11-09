import { UserJwtInterface } from "./src/core";

declare module "express-serve-static-core" {
    export interface Request {
        user?: UserJwtInterface;
    }
}
