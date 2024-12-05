import { NextFunction, Request, Response } from "express";
import { SOCKETEVENTS, STATUSCODE } from "../../../core";
import { SendMessageSchema } from "./message.validate";
import messageService from "./message.service";
import conversationService from "../conversation/conversation.service";
import { emitToPersonalRoom } from "../../../socketio/userRoom";

const messageController = {
    // get message
    getMessage: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: conversationId | lastMessageId | isAll: `yes` / `no` from query
            const conversationId = req.query.conversationId?.toString().trim();
            const lastMessageId = req.query.lastMessageId?.toString().trim();
            const isAll = req.query.isAll?.toString().trim();
            if (!conversationId) {
                return res.status(STATUSCODE.BAD).json({
                    msg: "Cần có conversationId từ query",
                });
            }

            const messages =
                isAll === "no" && lastMessageId
                    ? await messageService.getMessages(
                          conversationId,
                          lastMessageId
                      )
                    : await messageService.getAllMessageOfAnConversation(
                          conversationId
                      );

            return res.status(STATUSCODE.OK).json(messages);
        } catch (error) {
            next(error);
        }
    },
    // send message
    sendMessage: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: MessageCreateInterface from body
            // validate
            const validatedData = await SendMessageSchema().validateAsync(
                req.body
            );

            // check conversation exist
            const conversation = await conversationService.getConversationById(
                validatedData.conversation
            );
            if (!conversation)
                return res
                    .status(STATUSCODE.BAD)
                    .json("Đoạn chat này không tồn tại");

            // upload file
            const files = Array.isArray(req.files) ? req.files : undefined;

            const medias = files
                ? await messageService.uploadMessageFiles(files)
                : undefined;

            // create message and update lastmessage
            const message = await messageService.createMesage({
                ...validatedData,
                medias,
            });
            if (!message)
                return res
                    .status(STATUSCODE.BAD)
                    .json("Lỗi khi tạo message: Lỗi gì chả bít!");

            // find participants of conversation => emit

            conversation.participants.map((user) => {
                console.log(user._id.toString(), "user._id.toString()");
                emitToPersonalRoom(
                    user._id.toString(),
                    SOCKETEVENTS.RECEIVEMESSAGE,
                    message
                );
            });
            return res.status(STATUSCODE.OK).json(message);
        } catch (error) {
            next(error);
        }
    },
    // read message
    readMessage: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: messageId from query
            const messageId = req.query.messageId?.toString().trim();
            const userId = req.user?.id;
            if (!messageId || !userId) {
                return res.status(STATUSCODE.BAD).json({
                    msg: "Cần có messageId từ query hoặc bị lỗi userId",
                });
            }

            // read message
            const messageRead = await messageService.readMessage(
                messageId,
                userId
            );

            // emit
            if (messageRead) {
                const conversation =
                    await conversationService.getConversationById(
                        messageRead.conversation.toString()
                    );
                if (conversation) {
                    conversation.participants.map((user) => {
                        emitToPersonalRoom(
                            user._id.toString(),
                            SOCKETEVENTS.READMESSAGE,
                            messageRead
                        );
                    });
                }
            }

            return res.status(STATUSCODE.OK).json(messageRead);
        } catch (error) {
            next(error);
        }
    },
    // delete message
    deleteMessage: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: messageId from query
            const messageId = req.query.messageId?.toString().trim();
            if (!messageId) {
                return res.status(STATUSCODE.BAD).json({
                    msg: "Cần có messageId từ query",
                });
            }

            // delete
            const deletedMessage = await messageService.deleteMessage(
                messageId
            );

            // emit
            const conversation = deletedMessage
                ? await conversationService.getConversationById(
                      deletedMessage.conversation.toString()
                  )
                : null;
            if (conversation) {
                conversation.participants.map((user) => {
                    emitToPersonalRoom(
                        user._id.toString(),
                        SOCKETEVENTS.DELETEMESSAGE,
                        deletedMessage
                    );
                });
            }
            return res.status(STATUSCODE.OK).json(deletedMessage);
        } catch (error) {
            next(error);
        }
    },
};

export default messageController;
