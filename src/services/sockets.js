import { Server } from "socket.io";
import { messagesModel } from "../models/index.js";

const initSocket = (httpServer) => {
  let messages = [];

  setTimeout(() => {
    messages = [];
  }, 86400000);

  const socketServer = new Server(httpServer);

  socketServer.on("connection", (socket) => {
    console.log(`Cliente conectado; ID: ${socket.id}`);

    socket.emit("messageList", messages);

    socket.on("newMessage", (data) => {
      messages.push(data);
      const { user, message } = data;
      messagesModel.create({ user: user, message: message });
      console.log(`${user}: ${message}`);
      socket.emit(
        "secondMessage",
        `Mensaje de ${user} recibido en el servidor.`
      );
      socketServer.emit("messageArrived", data);
    });
  });

  return socketServer;
};

export default initSocket;
