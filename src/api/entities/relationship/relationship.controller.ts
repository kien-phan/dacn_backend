import { NextFunction, Request, Response } from "express";
import { STATUSCODE } from "../../../core";
import relationshipService from "./relationship.service";
import { relationshipCreateSchema } from "./relationship.validate";

const relationshipController = {
    // khi vao trang ca nhan cua nguoi khac
    getRelationShipTowardOneUser: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            // from query
            const user1 = req.query.user1?.toString().trim();
            const user2 = req.query.user1?.toString().trim();

            // check
            if (!user1 || !user2) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Thiếu query user1 hoặc user2" });
            }

            // get relationship
            const relationships =
                await relationshipService.getRelationShipTowardOneUser(
                    user1,
                    user2
                );

            return res.status(STATUSCODE.OK).json(relationships);
        } catch (error) {
            next(error);
        }
    },
    getFollowing: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // from query
            const userId = req.query.userId?.toString().trim();

            // check
            if (!userId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Thiếu query userId" });
            }

            // get
            const users = await relationshipService.getFollowing(userId);

            return res.status(STATUSCODE.OK).json(users);
        } catch (error) {
            next(error);
        }
    },
    getFollower: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // from query
            const userId = req.query.userId?.toString().trim();

            // check
            if (!userId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Thiếu query userId" });
            }

            // get
            const users = await relationshipService.getFollower(userId);

            return res.status(STATUSCODE.OK).json(users);
        } catch (error) {
            next(error);
        }
    },
    getFriend: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // from query
            const userId = req.query.userId?.toString().trim();

            // check
            if (!userId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Thiếu query userId" });
            }

            // get
            const users = await relationshipService.getAllFriend(userId);

            return res.status(STATUSCODE.OK).json(users);
        } catch (error) {
            next(error);
        }
    },
    addRelationShip: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            // require: user1, user2, relationship from body
            const validatedData =
                await relationshipCreateSchema().validateAsync(req.body);

            // create
            const newRelationship = await relationshipService.add1Relationship(
                validatedData.user1,
                validatedData.user2,
                validatedData.relationship
            );

            return res.status(STATUSCODE.OK).json(newRelationship);
        } catch (error) {
            next(error);
        }
    },
    delete1RelationShip: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            // require: user1, user2, relationship from body
            const validatedData =
                await relationshipCreateSchema().validateAsync(req.body);

            // create
            const deletedRelationship =
                await relationshipService.remove1Relationship(
                    validatedData.user1,
                    validatedData.user2,
                    validatedData.relationship
                );

            return res.status(STATUSCODE.OK).json(deletedRelationship);
        } catch (error) {
            next(error);
        }
    },
    getAllRelationships: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            const Relationships =
                await relationshipService.getAllRelationships();

            return res.status(STATUSCODE.OK).json(Relationships);
        } catch (error) {
            next(error);
        }
    },
};

export default relationshipController;
