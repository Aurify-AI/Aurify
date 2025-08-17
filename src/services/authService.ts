// NOTE: This auth system uses FP principles.
// TODO: Look into OOP implementation
// 

import { auth } from "@/lib/firebase"
import { createUserWithEmailAndPassword, PasswordValidationStatus, signInWithEmailAndPassword, User, validatePassword } from "firebase/auth"

export class PasswordError extends Error {
  // We omit these keys because they aren't neccessary for this error type
  // We also make this readonly because why would the property need to be modified (makes it like a const var)
  // Also this way we can use this for the login page :)
  readonly validationStatus: Omit<PasswordValidationStatus, 'isValid' | 'passwordPolicy'>
  constructor(validationStatus: Omit<PasswordValidationStatus, 'isValid' | 'passwordPolicy'>) {
    super(`Password is not valid!:\n
      ${Object.entries(validationStatus)
        // We want to filter out values that aren't covered by policy 
        .filter(([_,value]) => value === false)
        // Break this into key: value pairs, because verbosity isn't needed
        .map(([key, value]) => `${key}: ${value}`).join('\n')}\n
      `);
    this.validationStatus = validationStatus;
  }
}

export async function signIn(email: string, password: string): Promise<User> {
  const userCreds = await signInWithEmailAndPassword(auth, email, password);
  return userCreds.user;
}

export async function signUp(email: string, password: string): Promise<User> {
  // Check if passord matches current firebase password config
  const passwordValidationState = await validatePassword(auth, password);
  if (!passwordValidationState.isValid) {
    // If password can't be used
    throw new PasswordError(passwordValidationState);
  }
  const userCreds = await createUserWithEmailAndPassword(auth, email, password);
  return userCreds.user;
}

