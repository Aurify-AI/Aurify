import { firestore } from "firebase-functions";
import { FcmPayloadInterface, multicastNotifications, sendMultipleNotifications, sendSingleNotification } from "./notificationServiceHelper";
import { onRequest } from "firebase-functions/https";
import { db } from ".";
import { queuePostAtSpecifiedTime } from "./cloudTasks";

// import { onSchedule } from "firebase-functions/scheduler";

export const bookingSessionNotifications = {
  // Call this when the session is completed
  // Expects the tokens and payloads in body
  sendFeedbackNotification: onRequest(async (request, response) => {
    try {
      const data = request.body;
      sendMultipleNotifications(data.tokens, data.payloads);
      response.status(200).send("Notification Request Processed");
    } catch (error) {
      response.status(500).send("Failed to process notification request");
    }
  }),

  sendBookingRequestNotification: firestore.onDocumentUpdated(`bookings/{sessionId}`, async (event) => {
    const newValue = event.data?.after.data();
    const oldValue = event.data?.before.data();
    if (oldValue && newValue) {
      const addedUserIds = (newValue.requests || []).filter((id: string) => !(oldValue.requests || []).includes(id));
      //If a change was notified for other update and not new user, then don't worry.
      if (addedUserIds.length == 0) return;
      // Get the owner's FCM token to notify the owner
      const owner = newValue.owner;

      const ownerSnap = await db.collection("users").doc(owner).get();
      const ownerData = ownerSnap.data();

      if (!ownerData?.fcmToken) return;

      // Send the message here, with token identifying the target
      const fcmMessage: FcmPayloadInterface = {
        notification: {
          title: "Join request",
          body: "These users want to join your session",
        },
        data: {
          newUserIds: JSON.stringify(addedUserIds),
        },
      };
      sendSingleNotification(ownerData.fcmToken, fcmMessage);
    }
  }),

  // This sends the reminder, should only be called by the Google Cloud Tasks that will call at a scheduled time
  sendSessionReminder: onRequest(async (request, response) => {
    try {
      const data = request.body;
      const payload: FcmPayloadInterface = {
        notification: {
          title: "Meeting starts in 10 minutes",
        },
      };
      multicastNotifications(data.tokens, payload);
      response.status(200).send("Notification Request Processed");
    } catch (error) {
      response.status(500).send("Failed to process notification request");
    }
  }),

  queueSessionReminder: firestore.onDocumentCreated(`Bookings/{sessionId}`, async (event) => {
    const startTime = event.data?.data().startTime;
    const formattedStartTime = new Date(startTime);

    // subtracting 10 min
    const reminderTime = new Date(formattedStartTime.getTime() - 10 * 60 * 1000);
    await queuePostAtSpecifiedTime(reminderTime, "sendSessionReminder");
  }),
};
