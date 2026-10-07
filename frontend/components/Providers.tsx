"use client";
import type { ReactNode } from "react";
import { DataProvider } from "@/lib/data";
import { ToastProvider } from "@/lib/toast";
import { WalletProvider } from "@/lib/wallet";

export default function Providers({ children }: { children: ReactNode }) {
  return (
    <ToastProvider>
      <WalletProvider>
        <DataProvider>{children}</DataProvider>
      </WalletProvider>
    </ToastProvider>
  );
}
