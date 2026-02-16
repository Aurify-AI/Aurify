import * as admin from "firebase-admin";

export interface FcmPayloadInterface {
  data?: Record<string, string>; // optional key-value data
  notification: {
    title: string;
    body?: string;
  };
}

//send to a single user
export function sendSingleNotification(token: string, payload: FcmPayloadInterface) {
  const message = { token, ...payload };
  admin
    .messaging()
    .send(message)
    .then((response) => {
      console.log("Successfully sent message:", response);
      return;
    })
    .catch((error) => {
      console.error("Error sending message:", error);
      return;
    });
}

//send to multiusers, can be different messages
export function sendMultipleNotifications(tokens: string[], payloads: FcmPayloadInterface[]) {
  if (tokens.length !== payloads.length) {
    throw new Error("Tokens and payloads must have the same length");
  }
  const messages = tokens.map((token, index) => ({ token, ...payloads[index] }));
  admin
    .messaging()
    .sendEach(messages)
    .then((response) => {
      console.log("Successfully sent message:", response);
    })
    .catch((err) => console.error("Something went wrong with sending multiple notifications", err));
}

//send same message notification to multiple devices.
export function multicastNotifications(tokens: string[], payload: FcmPayloadInterface) {
  const message = {
    tokens,
    ...payload,
  };
  admin
    .messaging()
    .sendEachForMulticast(message)
    .then((response) => {
      console.log("Successfully sent message:", response);
      if (response.failureCount > 0) {
        const failedTokens: string[] = [];
        response.responses.forEach((resp, idx) => {
          if (!resp.success) failedTokens.push(tokens[idx]);
        });
        console.error("Tokens that failed:", failedTokens);
      }
    })
    .catch((err) => console.error("Error sending multicast:", err));
}
