const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();

// Replace with your environment variables or hardcode temporarily for testing
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "your_verify_token";
const APP_SECRET = process.env.APP_SECRET || "your_app_secret";

// Middleware to verify request signatures
function verifyRequestSignature(req, res, buf) {
    const signature = req.headers["x-hub-signature-256"];
    if (!signature) {
        console.warn("No signature found");
        return;
    }
    const elements = signature.split("=");
    const signatureHash = elements[1];
    const expectedHash = crypto
        .createHmac("sha256", APP_SECRET)
        .update(buf)
        .digest("hex");

    if (signatureHash !== expectedHash) {
        console.error("Invalid request signature.");
        throw new Error("Signature verification failed");
    }
}

// Use body-parser middleware with signature verification
app.use(bodyParser.json({ verify: verifyRequestSignature }));

// Webhook verification endpoint (GET)
app.get("/webhook", (req, res) => {
    console.log("VERIFY_TOKEN:", process.env.VERIFY_TOKEN);


    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];

    if (mode === "subscribe" && token === VERIFY_TOKEN) {
        console.log("WEBHOOK_VERIFIED");
        res.status(200).send(challenge);
    } else {
        res.sendStatus(403); // Forbidden if verification fails
    }
});

// Webhook event handling endpoint (POST)
app.post("/webhook", (req, res) => {
    const body = req.body;

    // Ensure this is an event from a page
    if (body.object === "page") {
        body.entry.forEach((entry) => {
            // Iterate over each messaging event
            const webhookEvent = entry.messaging[0];
            console.log("Received webhook event:", webhookEvent);

            // Process the event (e.g., log message content)
            if (webhookEvent.message) {
                const senderId = webhookEvent.sender.id;
                const messageText = webhookEvent.message.text;
                console.log(`Message from ${senderId}: ${messageText}`);

                // Example: Respond to the user (implement your logic here)
                // sendMessage(senderId, "Thanks for your message!");
            }
        });

        // Send 200 OK response to acknowledge receipt
        res.status(200).send("EVENT_RECEIVED");
    } else {
        res.sendStatus(404); // Not Found if not a page subscription
    }
});

// Function to send a message (implement your messaging logic here)
function sendMessage(recipientId, messageText) {
    console.log(`Sending message to ${recipientId}: ${messageText}`);
    // Add your logic to send a message using the Graph API
}

// Start the server
const PORT = process.env.PORT || 1337;
app.listen(PORT, () => console.log(`Webhook is running on port ${PORT}`));

