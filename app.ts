import express, { NextFunction, Request, Response } from "express";
import http from "http";
import helmet from "helmet";
import { Server as SocketIOServer } from "socket.io";
import cors from "cors";
import cookieParser from "cookie-parser";
import moment from "moment-timezone";
import rateLimit from "express-rate-limit";

import morgan from "morgan";
import dotenv from "dotenv";
import { SyntaxErrorWithStatus } from "./src/core/Interface";
import databases from "./src/config/Database.config";

dotenv.config();

// global var

// APP
const app = express();
const server = http.createServer(app);

// helmet
app.use(helmet());

if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
}

// socketio
const io = new SocketIOServer(server, {
    cors: {
        origin: function (origin, callback) {
            callback(null, true);
        },
        credentials: true,
        methods: ["GET", "POST"],
    },
});

// api cors
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "*");
    next();
});

app.use(
    cors({
        origin: function (origin, callback) {
            if (process.env.NODE_ENV === "production") {
                if (origin === `${process.env.FRONT_END_URL}`) {
                    callback(null, true);
                } else {
                    callback(new Error("Not allowed by CORS"));
                }
            } else {
                callback(null, true);
            }
        },
        credentials: true,
        methods: ["POST", "PUT", "PATCH", "GET", "OPTIONS", "HEAD", "DELETE"],
    })
);

// api
app.use(express.json());
app.use(cookieParser());

//morgan
morgan.token("date", (_req, _res, tz) => {
    return moment()
        .tz(tz as string)
        .format("YYYY-MM-DD HH:mm:ss");
});
morgan.format(
    "myformat",
    ':remote-addr - :remote-user [:date[Asia/Ho_Chi_Minh]] ":method :url HTTP/:http-version" :status :response-time ms'
);

app.use(morgan("myformat"));

//json err catch
app.use(
    (
        err: SyntaxErrorWithStatus,
        _req: Request,
        res: Response,
        next: NextFunction
    ) => {
        // Kiểm tra lỗi là do định dạng JSON không hợp lệ
        if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
            return res.status(400).json({ msg: "Định dạng JSON không hợp lệ" });
        } else {
            next();
        }
    }
);

//ratelimiter
const appLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    message: "Too many requests from this IP, please try again later",
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
app.use(appLimiter);

//routes
import routes from "./src/routes";
app.use(routes);

// connect to db
databases.mongodb.connect();

// socket namespaces

// firebase
import { initializeApp } from "firebase/app";
import firebaseConfig from "./src/config/Firebase.config";
initializeApp(firebaseConfig);

export default server;
