import { useState } from "react";

import { Dashboard } from "@/features/dashboard/Dashboard";
import { IdentityUnlock } from "@/features/auth/IdentityUnlock";
import { Workspace } from "@/features/workspace/Workspace";
import type { Identity } from "@/crypto/identity";
import { useStore } from "@/state/store";
import { useDesktopOpen } from "@/hooks/useDesktop";

export function App() {
  const session = useStore((s) => s.session);
  const [identity, setIdentity] = useState<Identity | null>(null);
  useDesktopOpen();

  if (session)
    return <Workspace />;
  if (identity)
    return <Dashboard identity={identity} onLock={() => setIdentity(null)} />;

  return <IdentityUnlock onUnlock={setIdentity} />;
}
