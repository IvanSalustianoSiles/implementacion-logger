export default class CustomError extends Error { // Hereda la clase nativa
    constructor(type, message = '') {
        super(message); // Invoca al constructor de la clase padre (Error) y le envía el mensaje.
        this.type = type;
    };
};
