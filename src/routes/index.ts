import express from "express";
const appRoutes = express.Router();

import createError from "http-errors";
import { NextFunction, Request, Response } from "express";

import userRoutes from "./user.route";

// appRoutes
appRoutes.use("/user", userRoutes);

// ping
appRoutes.get("/ping", (req: Request, res: Response, next: NextFunction) => {
    return res.status(200).json({ msg: "ping ping ping" });
});

// 400
appRoutes.use((req: Request, res: Response, next: NextFunction) => {
    next(createError(404, "Not Found"));
});

//joi validate
appRoutes.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (err.isJoi) {
        return res.status(400).json({
            status: 400,
            msg: err.details.map((detail: any) => detail.message),
        });
    }

    next(err);
});

//500
appRoutes.use((err: any, req: Request, res: Response, next: NextFunction) => {
    res.status(err.status || 500).json({
        status: err.status || 500,
        msg: err.message || "Server error 500",
    });
});

export default appRoutes;
