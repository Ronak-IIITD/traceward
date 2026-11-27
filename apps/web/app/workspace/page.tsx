import type { Metadata } from "next";
import { redirect } from "next/navigation";
import Workspace from "@/components/Workspace";
import { hasWorkspaceSession } from "@/lib/workspace-session";

export const metadata: Metadata = { title: "Scan workspace · TraceWard" };

export default async function WorkspacePage() {
  if (!(await hasWorkspaceSession())) redirect("/login");
  return <Workspace />;
}
