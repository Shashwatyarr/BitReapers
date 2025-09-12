// AuthContext.jsx
import { createContext, useContext, useEffect, useState } from "react";
import { supabase } from "../SupabaseClient";

const AuthContext = createContext();

export const AuthContextProvider = ({ children }) => {
  const [session, setSession] = useState(undefined);
  const [Loading,setLoading]=useState(true);
  // Sign up
  const signUpNewUser = async (email, password) => {
    const { data, error } = await supabase.auth.signUp({
    email: email.toLowerCase(),
    password: password,
  });

  if (error) {
    console.error("Error signing up: ", error);
    return { success: false, error };
  }

  if (data?.session) {
    setSession(data.session);
  }

  return { success: true, data };
  };

  // Sign in
  const signInUser = async (email, password) => {
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email: email.toLowerCase(),
        password: password,
      });

      if (error) {
        console.error("Sign-in error:", error.message);
        return { success: false, error: error.message };
      }
      if (data?.session) {
        setSession(data.session); // ✅ Yahan add kiya
      }

      return { success: true, data };
    } catch (err) {
      console.error("Unexpected error during sign-in:", err.message);
      return {
        success: false,
        error: "An unexpected error occurred. Please try again.",
      };
    }
  };

  // ✅ Google Sign-In
  const signInWithGoogle = async () => {
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: "google",
    });

    if (error) {
      console.error("Google sign-in error:", error.message);
      return { success: false, error: error.message };
    }

    return { success: true, data };
  };

  useEffect(() => {
    const getCurrentSession = async () => {
      const { data, error } = await supabase.auth.getSession();
      if (error) console.error("Get session error:", error.message);
      setSession(data?.session || null);
      setLoading(false);
    };
     getCurrentSession();
    
    const { data: listener } = supabase.auth.onAuthStateChange(
      (_event, newSession) => {
        setSession(newSession);
        setLoading(false);
      }
    );

    return () => {
      listener.subscription.unsubscribe();
    };
  }, []);

  // Sign out
  async function signOut() {
    const { error } = await supabase.auth.signOut();
    if (error) {
      console.error("Error signing out:", error);
    }
    setSession(null); 
  }

 function isLoggedIn(){
    return !!session;
  }

  return (
    <AuthContext.Provider
      value={{ signUpNewUser, signInUser, signInWithGoogle, session, signOut,isLoggedIn }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const UserAuth = () => {
  return useContext(AuthContext);
};
