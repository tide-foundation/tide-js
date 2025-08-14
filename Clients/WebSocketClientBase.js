export default async function WebSocketClientBase(url, protocols){
    if (!(this instanceof WebSocketClientBase)) {
        throw new Error("The 'AuthorizedEncryptionFlow' constructor must be invoked with 'new'.")
    }

    var base = this;
    const socket = new WebSocket(url, protocols);
    
    /**
     * @param {string} type 
     * @returns 
     */
    base.waitForMessage = async function(type){
        await waitForConnectionReady();
        return new Promise((resolve) => {
            const handler = (event) => {
                const data = JSON.parse(event.data);
                if(type === data.type){
                    // Correctly awaited type, return message
                    socket.removeEventListener("message", handler);
                    console.log("[WEBSOCKET] Recieved type: <" + responseTypeToAwait + "> successfully");
                    resolve(data.message);
                }
            };
            socket.addEventListener("message", handler);
        });
    }

    base.sendMessage = async function(msg){
        await waitForConnectionReady();
        socket.send(msg);
    }

    base.close = async function(){
        await waitForConnectionReady();
        socket.close();
    }

    async function waitForConnectionReady(){
        if(socket.readyState === socket.OPEN) return;
        if(socket.readyState === socket.CLOSED || socket.readyState === socket.CLOSING) throw `Socket is in the process of closing or is already closed`;

        const readyAwaiter = new Promise((res) => {
            socket.onopen = (event) => {
                res();
            }
            socket.onerror = (event) => {
                throw 'Error with websocket: ' + event;
            }
        });
        return readyAwaiter;
    }
}