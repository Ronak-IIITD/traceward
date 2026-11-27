"use client";

import { useActionState, useState } from "react";
import { signIn } from "./actions";

export default function SignInForm() {
  const [error, action, busy] = useActionState(signIn, "");
  const [visible, setVisible] = useState(false);

  return (
    <form className="entry-form" action={action}>
      <label htmlFor="workspace-key">Workspace key</label>
      <div className="entry-key">
        <input
          id="workspace-key"
          name="key"
          type={visible ? "text" : "password"}
          autoComplete="current-password"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={256}
          aria-invalid={!!error}
          aria-describedby={error ? "workspace-key-hint workspace-key-error" : "workspace-key-hint"}
          required
        />
        <button type="button" className="entry-toggle" onClick={() => setVisible(!visible)}>
          {visible ? "Hide" : "Show"}
        </button>
      </div>
      <p className="entry-hint" id="workspace-key-hint">
        Use your configured key or the key printed when you started TraceWard.
      </p>
      {error && (
        <p className="entry-error" id="workspace-key-error" role="alert">
          {error}
        </p>
      )}
      <button className="entry-primary entry-submit" disabled={busy}>
        {busy ? "Signing in…" : "Sign in"}
        <span aria-hidden="true">↗</span>
      </button>
    </form>
  );
}
