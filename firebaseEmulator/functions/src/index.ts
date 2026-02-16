import { setGlobalOptions } from "firebase-functions";

setGlobalOptions({ maxInstances: 10 });

import * as admin from "firebase-admin";
import { bookingSessionNotifications } from "./bookingSessionNotifications";

// Using admin permission to send notifications, when deploying only privileged owners should handle them to prevent spam
admin.initializeApp();
export const db = admin.firestore();

exports.sendFeedbackNotification = bookingSessionNotifications.sendFeedbackNotification;
exports.sendBookingRequestNotification = bookingSessionNotifications.sendBookingRequestNotification;
exports.sendSessionReminder = bookingSessionNotifications.sendSessionReminder;
exports.queueSessionReminder = bookingSessionNotifications.queueSessionReminder;
