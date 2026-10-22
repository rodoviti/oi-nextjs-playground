"use client";

import { useEffect, useRef } from "react";

export default function CompleteLogin() {
  const notified = useRef(false);
  useEffect(() => {
    if (notified.current) return;
    notified.current = true;
    const params = new URLSearchParams(window.location.search);
    window.history.replaceState(null, "", "/auth/complete");
    if (window.opener) {
      window.opener.postMessage({
        type: "spid-login",
        requestId: params.get("requestId"),
        error: params.get("error") ?? "LoginFailed",
      }, window.location.origin);
      window.close();
    }
  }, []);
  return <main><p>Login completato. Puoi chiudere questa finestra e tornare alla pagina principale.</p></main>;
}
