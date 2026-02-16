//Possible improvements to querying later
//We add the session doc id into one of the user's field, this way when retrieving the scheduled sessions, it's easier and not having to look through the participants array to check.
//(Issue: when accepting a join request, the owner will write in the client's doc which is a breach of security rules)
//
// await updateDoc(doc(db, USERS_COLLECTION, user.uid), {
//   scheduledSessions: arrayUnion(newDocRef.id)
// })
import { auth, db } from "@/lib/firebase";
import {
  addDoc,
  arrayRemove,
  arrayUnion,
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  or,
  query,
  updateDoc,
  where,
} from "firebase/firestore";

export enum ServiceType {
  Interview,
  Speech,
  //And so on
}

interface BookingSession {
  sessionName: string;
  owner: string;
  participantIds: string[];
  status: string;
  startTime: string;
  endTime: string;
  service: ServiceType;
  requests: string[];
}

interface BookingFormInput {
  startTime: Date;
  endTime: Date;
  service: ServiceType;
}

interface BookingSearchParams {
  time: Date;
  service: ServiceType;
}

const BOOKINGS_COLLECTION = "bookings";

export const postBookingSession = async ({ startTime, endTime, service }: BookingFormInput) => {
  const user = auth.currentUser;
  try {
    const booking = {
      owner: user.uid,
      participantIds: [],
      status: "Open",
      startTime: startTime.toUTCString(),
      endTime: endTime.toUTCString(),
      service: service,
    };

    await addDoc(collection(db, BOOKINGS_COLLECTION), 
      booking,
    );
  } catch (e) {
    console.error("Error adding booking session: ", e);
  }
};

export const deleteBookingSession = async (sessionId: string) => {
  try {
    const toDeleteRef = doc(db, BOOKINGS_COLLECTION, sessionId);
    await deleteDoc(toDeleteRef);
  } catch (e) {
    console.error("Error deleting booking session: ", e);
  }
};

export const getCurUserScheduledSessions = async () => {
  try {
    const user = auth.currentUser;
    const q = query(
      collection(db, BOOKINGS_COLLECTION),
      or(where("owner", "==", user.uid), where("participantIds", "array-contains", user.uid))
    );
    const snap = await getDocs(q);

    const results: BookingSession[] = snap.docs.map((doc) => ({
      ...(doc.data() as BookingSession),
      sessionId: doc.id,
    }));

    return results;
  } catch (e) {
    console.error("Error getting current user scheduled sessions: ", e);
    return [];
  }
};

export const getBookingSessionInfo = async (sessionId: string) => {
  try {
    const ref = doc(db, BOOKINGS_COLLECTION, sessionId);
    return (await getDoc(ref)).data() as BookingSession;
  } catch (e) {
    console.error("Error getting booking session info: ", e);
    return null;
  }
};

export const searchBookingSessions = async ({ service, time }: BookingSearchParams) => {
  try {
    const q = query(
      collection(db, BOOKINGS_COLLECTION),
      where("status", "==", "Open"),
      where("service", "==", service),
      where("startTime", "<=", time.toUTCString()),
      where("endTime", ">=", time.toUTCString())
    );

    const snap = await getDocs(q);
    const results: BookingSession[] = snap.docs.map((doc) => ({
      ...(doc.data() as BookingSession),
      sessionId: doc.id,
    }));
    return results;
  } catch (e) {
    console.error("Error searching booking sessions: ", e);
    return [];
  }
};

export const requestToJoinBooking = async (sessionId: string) => {
  try {
    const user = auth.currentUser;
    const ref = doc(db, BOOKINGS_COLLECTION, sessionId);

    await updateDoc(ref, { requests: arrayUnion(user.uid) });
  } catch (e) {
    console.error("Error requesting to join booking: ", e);
  }
};

export const acceptBookingRequest = async (sessionId: string, userId: string) => {
  try {
    const ref = doc(db, BOOKINGS_COLLECTION, sessionId);
    await updateDoc(ref, {
      userIds: arrayUnion(userId),
      requests: arrayRemove(userId),
    });
  } catch (e) {
    console.error("Error accepting booking request: ", e);
  }
};

export const rejectBookingRequest = async (sessionId: string, userId: string) => {
  try {
    const ref = doc(db, BOOKINGS_COLLECTION, sessionId);
    await updateDoc(ref, {
      requests: arrayRemove(userId),
    });
  } catch (e) {
    console.error("Error rejecting booking request: ", e);
  }
};
