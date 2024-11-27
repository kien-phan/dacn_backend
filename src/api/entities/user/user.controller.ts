import { NextFunction, Request, Response } from "express";
import { STATUSCODE } from "../../../core";
import userService from "./user.service";

const userController = {
    getUserById: async (req: Request, res: Response, next: NextFunction) => {
        // require: userId from query
        const userId = req.query.userId?.toString().trim();

        if (!userId) {
            return res
                .status(STATUSCODE.BAD)
                .json({ msg: "Cần có userId từ query" });
        }

        // search
        const users = await userService.getUserById(userId);

        return res.status(STATUSCODE.OK).json(users);
    },
    searchUser: async (req: Request, res: Response, next: NextFunction) => {
        // require: searchText from query
        const searchText = req.query.searchText?.toString().trim();

        if (!searchText) {
            return res
                .status(STATUSCODE.BAD)
                .json({ msg: "Cần có searchText từ query" });
        }

        // search
        const users = await userService.searchUser(searchText);

        return res.status(STATUSCODE.OK).json(users);
    },
    getAllUsers: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const users = await userService.getAllUsers();

            return res.status(STATUSCODE.OK).json(users);
        } catch (error) {
            next(error);
        }
    },
};

export default userController;
