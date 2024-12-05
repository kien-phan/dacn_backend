import mongoose from "mongoose";
import conversationModel from "./conversation.model";
import messageModel from "../message/message.model";
import postService from "../post/post.service";

const conversationService = {
    getConversationsOfOneUser: async (userId: string) => {
        const userObjectId = new mongoose.Types.ObjectId(userId);
        // Tìm tất cả các conversations của user
        const conversations = await conversationModel
            .find({
                participants: userObjectId,
            })
            .populate([
                { path: "participants" }, // Populate participants
                {
                    path: "lastMessage",
                    populate: { path: "sender" }, // Nested populate: lastMessage.sender
                },
            ]);

        // Lọc các conversation có ít nhất 1 message
        const filteredConversations = conversations.filter(
            (conversation) => conversation.lastMessage
        );

        return filteredConversations;
    },
    getExistedConversation: async (type: string, participants: string[]) => {
        const existingConversation = await conversationModel
            .findOne({
                type: type,
                participants: {
                    $all: participants,
                    $size: participants.length,
                }, // Kiểm tra đủ và đúng các participants
            })
            .populate([
                { path: "participants" }, // Populate participants
                {
                    path: "lastMessage",
                    populate: { path: "sender" }, // Nested populate: lastMessage.sender
                },
            ])
            .exec();

        return existingConversation;
    },
    getConversationById: async (conversationId: string) => {
        const conversation = await conversationModel
            .findById(conversationId)
            .populate([
                { path: "participants" }, // Populate participants
                {
                    path: "lastMessage",
                    populate: { path: "sender" }, // Nested populate: lastMessage.sender
                },
            ])
            .exec();

        return conversation;
    },
    createConversation: async (type: string, participants: string[]) => {
        const newConversation = new conversationModel({
            type,
            participants,
        });

        await newConversation.save();

        await newConversation.populate([
            { path: "participants" }, // Populate participants
            {
                path: "lastMessage",
                populate: { path: "sender" }, // Nested populate: lastMessage.sender
            },
        ]);
        return newConversation;
    },
    deleteOneConversation: async (conversationId: string) => {
        const session = await mongoose.startSession();
        let deletedConversation;
        await session.withTransaction(async () => {
            // Xoá Conversation
            deletedConversation = await conversationModel
                .findByIdAndDelete(conversationId)
                .populate([
                    { path: "participants" }, // Populate participants
                    {
                        path: "lastMessage",
                        populate: { path: "sender" }, // Nested populate: lastMessage.sender
                    },
                ])
                .exec();

            if (!deletedConversation) {
                throw new Error("Conversation not found");
            }

            // xoa medias cua message
            const messages = await messageModel.find({
                conversation: conversationId,
            });
            const mediaSources = messages.reduce(
                (sources: string[], message) => {
                    if (message.medias && message.medias.length > 0) {
                        const sourcesFromMedia = message.medias.map(
                            (media) => media.source
                        );
                        sources.push(...sourcesFromMedia);
                    }
                    return sources;
                },
                []
            );
            await postService.deleteImages(mediaSources);

            // Xoá Messages liên quan
            await messageModel.deleteMany({ conversation: conversationId });
        });
        session.endSession();

        return deletedConversation;
    },
};

export default conversationService;
