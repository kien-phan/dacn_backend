import mongoose from "mongoose";
import relationshipModel from "./relationship.model";

const relationshipService = {
    getAllRelationships: async () => {
        return await relationshipModel.find().lean();
    },
    getAllFriend: async (userId: string) => {
        const friends = await relationshipModel
            .find({
                user1: userId,
                relationship: "friend",
            })
            .populate("user2")
            .exec();

        return friends.map((rel) => rel.user2);
    },
    getFollower: async (userId: string) => {
        const followers = await relationshipModel
            .find({
                user2: userId,
                relationship: "following",
            })
            .populate("user1")
            .exec();

        return followers.map((rel) => rel.user1);
    },
    getFollowing: async (userId: string) => {
        const following = await relationshipModel
            .find({
                user1: userId,
                relationship: "following",
            })
            .populate("user2")
            .exec();

        return following.map((rel) => rel.user2);
    },
    getRelationShipTowardOneUser: async (user1: string, user2: string) => {
        const relationships = await relationshipModel.find({
            user1: user1,
            user2: user2,
        });

        return relationships;
    },
    add1Relationship: async (
        user1: string,
        user2: string,
        relationship: string
    ) => {
        // create relationship
        const newRelationship = new relationshipModel({
            user1: new mongoose.Types.ObjectId(user1),
            user2: new mongoose.Types.ObjectId(user2),
            relationship,
        });
        await newRelationship.save();

        return newRelationship;
    },
    remove1Relationship: async (
        user1: string,
        user2: string,
        relationship: string
    ) => {
        // delete if relationship is empty
        await relationshipModel.findOneAndDelete({
            user1,
            user2,
            relationship,
        });
    },
    removeAllRelationship: async (user: string) => {
        await relationshipModel.deleteMany({
            $or: [{ user1: user }, { user2: user }],
        });
    },
};

export default relationshipService;
