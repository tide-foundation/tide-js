export default function WebSocketClientBase(url, protocols){
    if (!(this instanceof WebSocketClientBase)) {
        throw new Error("The 'AuthorizedEncryptionFlow' constructor must be invoked with 'new'.")
    }

    var base = this;
    const socket = new WebSocket(url, protocols);

    base.getSocketUrl = () => socket.url;
    
    /**
     * @param {string} type 
     * @returns 
     */
    base.waitForMessage = async function(type){
        return new Promise((resolve) => {
            const handler = (event) => {
                const data = JSON.parse(event.data);
                if(type === data.type){
                    // Correctly awaited type, return message
                    socket.removeEventListener("message", handler);
                    console.log("[WEBSOCKET] Recieved type: <" + type + "> successfully");
                    resolve(data.message);
                }
            };
            socket.onmessage = e => handler(e);
        });
    }

    base.sendMessage = async function(msg){
        await waitForConnectionReady();
        socket.send(JSON.stringify(msg));
    }

    base.close = async function(){
        await waitForConnectionReady();
        socket.close();
    }

    async function waitForConnectionReady(){
        if(socket.readyState === socket.OPEN) return;
        if(socket.readyState === socket.CLOSED || socket.readyState === socket.CLOSING) throw `Socket is in the process of closing or is already closed`;

        const readyAwaiter = new Promise((res) => {
            socket.onopen = () => res();
            socket.onerror = (event) => {
                throw event;
            }
        });
        return readyAwaiter;
    }
}