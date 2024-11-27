// SCHEMANAME
export const SCHEMANAME = {
    USER: "user",
    USER_SAVE: "user_save",
    FRIEND: "friend",
    POST_INTERACTED: "post_interacted",
    POST: "post",
    POST_COMMENT: "post_comment",
    CHAT_CHANNEL: "chat_channel",
    CHAT_CONTENT: "chat_content",
};

// MESSAGE
export const MESSAGE = {
    INITFAILNOTIFNAMESPACE: "Chưa khỏi tạo nt nsp",
    TOKENEXPIRE: "Token đã hết hạn vui lòng đăng nhập lại!",
    ACCOUNTBLOCK: "Tài khoản của bạn đã bị khoá",
    LOGINREQUIRE: "Bạn cần phải đăng nhập",
    NOPERMISSION: "Bạn không có quyền làm điều này!",
    PARAMSNEEDED: "Params needed!",
    WRONGACCOUNTFORMAT:
        "Tài khoản không đúng định dạng. Hãy nhập email hoặc số điện thoại",
    UNKNOWNERROR: "Lỗi gì chả biết nữa!",
};

// STATUS CODE
export const STATUSCODE = {
    OK: 200,
    UNAUTH: 401,
    FORBIDDEN: 403,
    BAD: 400,
    SERVERERROR: 500,
};

// RATE LIMIT
import rateLimit from "express-rate-limit";
export const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 50, // Limit each IP to 5 create account requests per `window` (here, per hour)
    message:
        "Too many accounts created from this IP, please try again after an hour",
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
