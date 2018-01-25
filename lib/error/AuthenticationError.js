class AuthenticationError extends Error {
    constructor(message) {
        if (message instanceof Error) {
            super(message.message);
            Object.assign(this, message);
        }
        else super(message);
        this.name = 'AuthenticationError';
    }
}

module.exports = AuthenticationError;