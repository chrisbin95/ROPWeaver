import { initializeApp } from 'firebase/app';
import { getFirestore, collection, getDocs, query, where } from 'firebase/firestore';

export const firebaseConfig = {
  apiKey: "AIzaSyDZ3BEfUstg32hqnbctG7X3LQ5onNJ98qs",
  authDomain: "ropweaver.firebaseapp.com",
  projectId: "ropweaver",
  storageBucket: "ropweaver.firebasestorage.app",
  messagingSenderId: "356547989098",
  appId: "1:356547989098:web:16a48b40d0bde270df8413",
  measurementId: "G-CR1P508GPH"
};

export const app = initializeApp(firebaseConfig);
export const db = getFirestore(app);
export { collection, getDocs, query, where };
