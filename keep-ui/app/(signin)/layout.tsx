import { Card } from "@tremor/react";
import Image from "next/image";

export const metadata = {
  title: "Sampark",
  description: "The open-source alert management and AIOps platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="bg-tremor-background-subtle">
      <body>
        <div className="min-h-screen flex items-center justify-center bg-tremor-background-subtle p-4">
          <div className="flex flex-col items-center gap-6">
            <Image
              src="/sampark-logo.png"
              alt="Sampark Softwares"
              width={199}
              height={74}
              priority
              className="object-contain"
            />
            <Card
              className="w-full max-w-md p-8 min-w-96 flex flex-col gap-6 items-center"
              decoration="top"
              decorationColor="orange"
            >
              {children}
            </Card>
          </div>
        </div>
      </body>
    </html>
  );
}
