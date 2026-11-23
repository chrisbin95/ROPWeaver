import { initializeApp } from 'firebase/app';
import { getFirestore, collection, getDocs, query, where, limit, startAfter, getCountFromServer } from 'firebase/firestore';

export const firebaseConfig = {
  apiKey: "AIzaSyDSdptZ1bsqDwflZQ3QiT1fVZvfGFRF8mo",
  authDomain: "rop-weaver.firebaseapp.com",
  projectId: "rop-weaver",
  storageBucket: "rop-weaver.firebasestorage.app",
  messagingSenderId: "466790753632",
  appId: "1:466790753632:web:f8d0286a3a77f6a6bd6a05",
  measurementId: "G-6GL8BCHHB3"
};

export const app = initializeApp(firebaseConfig);
export const db = getFirestore(app);
export { collection, getDocs, query, where, limit, startAfter, getCountFromServer };
