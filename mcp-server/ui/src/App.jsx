import React from "react";
import AuthGate from "./AuthGate.jsx";
import AppCore from "./AppCore.jsx";

export default function App() {
  return (
    <AuthGate>
      <AppCore />
    </AuthGate>
  );
}
