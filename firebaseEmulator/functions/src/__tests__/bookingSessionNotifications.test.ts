import * as admin from "firebase-admin";

const projectId = "demo-myapp";
process.env.GCLOUD_PRJECT = projectId;
process.env.FIRESTORE_EMULATOR_HOST = "localhost:8080";

// Make sure to have a running emulator beforehand, this connects to the firebase SDK to access that emulator.
admin.initializeApp({ projectId });
const db = admin.firestore();

// To reset collection every run
beforeAll(async () => {
  await admin.firestore().recursiveDelete(admin.firestore().collection("users"));
  await admin.firestore().recursiveDelete(admin.firestore().collection("bookings"));

  const users = [
    { name: "Alice", age: 70, fcmToken: "token_1" },
    { name: "Bob", age: 35, fcmToken: "token_2" },
    { name: "Charlie", age: 42, fcmToken: "token_3" },
  ];

  //store created user doc IDs
  const userIds: string[] = [];

  for (const user of users) {
    const docRef = await db.collection("users").add(user);
    userIds.push(docRef.id);
  }

  const bookingSessions = [
    {
      sessionName: "Session 1",
      owner: userIds[0],
      participantIds: [],
      status: "open",
      startTime: "2025-11-24 00:24:55 UTC",
      endTime: "2025-11-24 01:24:55 UTC",
      service: "",
      requests: [],
    },
  ];

  for (const bookingSession of bookingSessions) {
    await db.collection("bookings").add(bookingSession);
  }
});

// Need to set up actual FCM in client side and use that to complete integration test, for now we can see that firebase functions get triggered through the console
describe("Booking Session Notifications", () => {
  // Update a field in collection -> triggers firebase function -> sends FCM request
  it("Testing sendBookingRequestNotification function triggers when requests field is updated", async () => {
    const snapshot = await db.collection("bookings").where("sessionName", "==", "Session 1").get();
    await Promise.all(
      snapshot.docs.map((doc) =>
        doc.ref.update({
          requests: admin.firestore.FieldValue.arrayUnion({ requests: "ID of a user" }),
        })
      )
    );

    // Take into consideration the race condition for the trigger to happen
    await new Promise((r) => setTimeout(r, 3000));
  });

  // Setting time for a session -> queue task on google cloud tasks -> which will trigger firebase function when time is right -> send FCM request
  it("Testing queue and send session reminders works with google cloud task", async () => {
    const bookingSession = [
      {
        sessionName: "Test Session",
        status: "open",
        startTime: "2025-11-24 00:24:55 UTC",
        endTime: "2025-11-24 01:24:55 UTC",
        service: "",
        requests: [],
      },
    ];
    await db.collection("bookings").add(bookingSession);
  });
});
