import { NextFunction, Request, Response } from "express";
import { CreateConversationSchema } from "./conversation.validate";
import conversationService from "./conversation.service";
import { STATUSCODE } from "../../../core";

const conversationController = {
    // getConversationOfOneUser
    getConversationOfOneUser: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            // require: userId from query
            const userId = req.query.userId?.toString().trim();
            if (!userId) {
                return res.status(STATUSCODE.BAD).json({
                    msg: "Cần có userId từ query",
                });
            }

            const conversations =
                await conversationService.getConversationsOfOneUser(userId);

            return res.status(STATUSCODE.OK).json(conversations);
        } catch (error) {
            next(error);
        }
    },
    // createConversation
    createConversation: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            // require: type & participants from body | type can be: `personal | group`
            const validatedData =
                await CreateConversationSchema().validateAsync(req.body);
            // checkExist
            const existedConversation =
                await conversationService.getExistedConversation(
                    validatedData.type,
                    validatedData.participants
                );

            if (existedConversation) {
                return res.status(STATUSCODE.OK).json(existedConversation);
            }
            // create
            const newConversation =
                await conversationService.createConversation(
                    validatedData.type,
                    validatedData.participants
                );
            return res.status(STATUSCODE.OK).json(newConversation);
        } catch (error) {
            next(error);
        }
    },
    // deleteConversation
    deleteConversation: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            // require: conversationId from query
            const conversationId = req.query.conversationId?.toString().trim();
            if (!conversationId) {
                return res.status(STATUSCODE.BAD).json({
                    msg: "Cần có conversationId từ query",
                });
            }

            // delete
            const deletedConversation =
                await conversationService.deleteOneConversation(conversationId);

            return res.status(STATUSCODE.OK).json(deletedConversation);
        } catch (error) {
            next(error);
        }
    },
};

export default conversationController;
