"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Skeleton } from "@/components/ui";

// Old report links now open the Findings tab of the engagement page.
export default function ReportRedirect({ params }: { params: { id: string } }) {
  const router = useRouter();
  useEffect(() => {
    router.replace(`/engagements/${params.id}?tab=findings`);
  }, [params.id, router]);
  return <Skeleton h={300} />;
}
