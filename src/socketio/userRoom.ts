import { Server } from "socket.io";

let socketio: Server;

export const socketIoInit = (io: Server) => {
    socketio = io;
    io.on("connection", (socket) => {
        const userId = socket.handshake.query.userId as string; // Lấy user ID từ query hoặc thông tin đăng nhập

        if (!userId) {
            console.error("Missing userId in handshake query");
            return;
        }

        socket.join(userId); // Thêm socket vào room có tên là userId
    });
};

export const emitToPersonalRoom = (room: string, event: string, data: any) => {
    if (socketio) {
        socketio.to(room).emit(event, data);
    } else {
        console.error("fail to init user namespace");
    }
};

// const [socket, setSocket] = useState(null);
//     const [userId] = useState('user123'); // Đây là ID của người dùng (thay bằng giá trị thực tế)

//     useEffect(() => {
//         // Kết nối tới server và gửi userId qua query string
//         const newSocket = io('http://localhost:4000', {
//             query: { userId }, // Gửi userId khi kết nối
//         });

//         setSocket(newSocket);

//         // Dọn dẹp khi component unmount
//         return () => {
//             newSocket.disconnect();
//         };
//     }, [userId]);
