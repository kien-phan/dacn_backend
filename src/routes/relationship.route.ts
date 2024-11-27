import express from "express";
const relationshipRoutes = express.Router();

import { authMiddleware } from "../api/middlewares/auth.middleware";
import relationshipController from "../api/entities/relationship/relationship.controller";

// khi vao trang ca nhan => get your relationship toward that user
relationshipRoutes.get(
    "/getRelationShipTowardOneUser",
    authMiddleware.verifyToken,
    relationshipController.getRelationShipTowardOneUser
);

// get follwing of someone
relationshipRoutes.get(
    "/getFriend",
    authMiddleware.verifyToken,
    relationshipController.getFriend
);

// get follwing of someone
relationshipRoutes.get(
    "/getFollowing",
    authMiddleware.verifyToken,
    relationshipController.getFollowing
);

// get follower of someone
relationshipRoutes.get(
    "/getFollower",
    authMiddleware.verifyToken,
    relationshipController.getFollower
);

// create
relationshipRoutes.post(
    "/create",
    authMiddleware.verifyToken,
    relationshipController.addRelationShip
);

// delete
relationshipRoutes.post(
    "/delete",
    authMiddleware.verifyToken,
    relationshipController.delete1RelationShip
);

// get all relationships
relationshipRoutes.get(
    "/getAllRelationships",
    relationshipController.getAllRelationships
);

export default relationshipRoutes;
