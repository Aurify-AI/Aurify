import { onSchedule } from "firebase-functions/scheduler";
import { db } from ".";
import { FcmPayloadInterface, multicastNotifications } from "./notificationServiceHelper";

export const checkInNotifications = {
  dailyReminder: onSchedule("every day 9:00", async (event) => {
    const snapshot = await db.collection("users").get();

    //collect all FCM tokens
    const tokens: string[] = [];
    snapshot.forEach((doc) => {
      const userData = doc.data();
      if (userData.fcmToken) tokens.push(userData.fcmToken);
    });

    //no tokens, nothing to do
    if (tokens.length === 0) return;

    const message: FcmPayloadInterface = {
      notification: {
        title: "Daily check-in",
        body: "Log in for rewards",
      },
    };

    multicastNotifications(tokens, message);
  }),
};
